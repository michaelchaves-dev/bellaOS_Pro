"""Slice 2 tests — the Receipts Engine.

Covers: hash-chain tamper evidence (field tamper, reorder, deletion,
forged append), the query API, Decimal cost-ledger reconciliation,
the plain-language renderer, and the supervisor integration (opt-in
store streaming) — including that a run without the store behaves
exactly as before.
"""

import json
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

from bellaos_pro import (
    Authority,
    PermissionLevel,
    Principal,
    ProposedStep,
    Route,
    ScopeContract,
    run_pipeline,
)
from bellaos_pro.receipts import ReceiptStore, record_hash, verify_chain

TASK = "Summarize this week's rent roll and flag anomalies."


def _authority():
    owner = Principal.owner("Michael")
    auth = Authority()
    auth.set_permission("summarize", PermissionLevel.ALONE, principal=owner)
    return auth


def _contract(budget):
    return ScopeContract(
        task=TASK,
        problem="The weekly rent roll takes an hour to review by hand.",
        scope="Read the rent-roll export and produce an anomaly summary.",
        output_contract="A one-page anomaly report.",
        requester="Michael",
        budget=budget,
    )


def _route():
    return [Route("sum-basic", "summarize", 1, "0.40")]


def _mixed_steps():
    """One executed, one subtracted, one denied (capability not held)."""
    return [
        ProposedStep(
            capability="summarize",
            action="Read the rent-roll export",
            serves_scope="Provides the data for the anomaly report.",
        ),
        ProposedStep(
            capability="summarize",
            action="Book a flight to Boston",
            serves_scope="",
        ),
        ProposedStep(
            capability="mail",
            action="Email the report to the owner",
            serves_scope="Delivers the output contract.",
        ),
    ]


def _run_mixed(store=None, run_id=None):
    return run_pipeline(
        TASK,
        _contract("5.00"),
        _authority(),
        steps=_mixed_steps(),
        held_capabilities={"summarize"},
        routes=_route(),
        receipt_store=store,
        run_id=run_id,
    )


def _run_budget_halt(store=None, run_id=None):
    """Executed, subtracted, executed, then the budget ceiling hits."""
    steps = [
        ProposedStep("summarize", "Summarize page one of the export",
                     serves_scope="Part of the anomaly summary."),
        ProposedStep("summarize", "Book a flight to Boston",
                     serves_scope=""),
        ProposedStep("summarize", "Summarize page two of the export",
                     serves_scope="Part of the anomaly summary."),
        ProposedStep("summarize", "Summarize page three of the export",
                     serves_scope="Part of the anomaly summary."),
    ]
    return run_pipeline(
        TASK,
        _contract("1.00"),
        _authority(),
        steps=steps,
        held_capabilities={"summarize"},
        routes=_route(),
        receipt_store=store,
        run_id=run_id,
    )


class StoreTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "receipts.jsonl"
        self.store = ReceiptStore(self.path)

    def _lines(self):
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def _rewrite(self, records):
        self.path.write_text(
            "".join(json.dumps(r) + "\n" for r in records),
            encoding="utf-8",
        )


class TestChainVerification(StoreTestCase):
    def setUp(self):
        super().setUp()
        _run_mixed(store=self.store, run_id="run-a")

    def test_clean_chain_verifies(self):
        ok, bad, reason = verify_chain(self.store.records())
        self.assertTrue(ok, reason)
        self.assertIsNone(bad)

    # (a) a field tampered after writing
    def test_tampered_field_fails_at_that_index(self):
        records = self._lines()
        records[3]["receipt"]["details"]["scope"] = "tampered scope"
        self._rewrite(records)
        ok, bad, reason = verify_chain(self.store.records())
        self.assertFalse(ok)
        self.assertEqual(bad, 3)
        self.assertIn("hash", reason)

    # (b) two receipts reordered
    def test_swapped_receipts_fail(self):
        records = self._lines()
        records[1], records[2] = records[2], records[1]
        self._rewrite(records)
        ok, bad, reason = verify_chain(self.store.records())
        self.assertFalse(ok)
        self.assertEqual(bad, 1)

    # (c) a receipt deleted mid-chain
    def test_deleted_middle_receipt_fails(self):
        records = self._lines()
        del records[4]
        self._rewrite(records)
        ok, bad, reason = verify_chain(self.store.records())
        self.assertFalse(ok)
        self.assertEqual(bad, 4)

    # (d) a forged receipt appended with a wrong prev_hash
    def test_forged_append_fails(self):
        n = len(self._lines())
        body = {
            "run_id": "run-a",
            "seq": n,
            "prev_hash": "f" * 64,
            "receipt": {
                "seq": 99,
                "stage": "Step:9",
                "status": "EXECUTED",
                "ts": 0.0,
                "details": {"decision": "EXECUTED", "cost": 0.0},
            },
        }
        forged = dict(body)
        forged["hash"] = record_hash(body)  # self-consistent, wrong link
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(forged) + "\n")
        ok, bad, reason = verify_chain(self.store.records())
        self.assertFalse(ok)
        self.assertEqual(bad, n)
        self.assertIn("prev_hash", reason)


class TestQuery(StoreTestCase):
    def setUp(self):
        super().setUp()
        _run_mixed(store=self.store, run_id="run-a")
        run_pipeline(
            TASK,
            _contract("5.00"),
            _authority(),
            steps=[
                ProposedStep(
                    "summarize",
                    "Read the rent-roll export",
                    serves_scope="Provides the data for the anomaly report.",
                )
            ],
            held_capabilities={"summarize"},
            routes=_route(),
            receipt_store=self.store,
            run_id="run-b",
        )

    # (e) query filters return exactly the matching receipts
    def test_query_filters(self):
        by_run = self.store.query(run_id="run-a")
        self.assertEqual(len(by_run), 9)  # 5 intake + 3 steps + closeout
        self.assertTrue(all(r["run_id"] == "run-a" for r in by_run))

        subtracted = self.store.query(decision="SUBTRACTED")
        self.assertEqual(len(subtracted), 1)
        self.assertEqual(subtracted[0]["run_id"], "run-a")
        self.assertEqual(
            subtracted[0]["receipt"]["details"]["action"],
            "Book a flight to Boston",
        )

        closeouts = self.store.query(stage="Closeout")
        self.assertEqual(len(closeouts), 2)
        self.assertEqual({r["run_id"] for r in closeouts}, {"run-a", "run-b"})

        mail = self.store.query(capability="mail")
        self.assertEqual(len(mail), 1)
        self.assertEqual(mail[0]["receipt"]["details"]["decision"], "DENIED")

        executed_b = self.store.query(run_id="run-b", decision="EXECUTED")
        self.assertEqual(len(executed_b), 1)


class TestCostLedger(StoreTestCase):
    # (f) ledger totals equal hand-summed receipt costs for a mixed run
    def test_ledger_reconciles_with_receipts(self):
        _run_mixed(store=self.store, run_id="run-a")
        ledger = self.store.cost_ledger()

        hand = sum(
            (
                Decimal(str(r["receipt"]["details"].get("cost", 0)))
                for r in self.store.records()
                if r["receipt"]["status"] == "EXECUTED"
            ),
            Decimal("0"),
        )
        self.assertEqual(hand, Decimal("0.4"))
        self.assertEqual(ledger["total"], hand)
        self.assertEqual(ledger["per_run"], {"run-a": Decimal("0.4")})
        self.assertEqual(ledger["per_capability"], {"summarize": Decimal("0.4")})
        self.assertEqual(ledger["per_route"], {"sum-basic": Decimal("0.4")})

        closeout = self.store.query(stage="Closeout")[0]
        self.assertEqual(
            Decimal(str(closeout["receipt"]["details"]["total_cost"])),
            ledger["per_run"]["run-a"],
        )


class TestRenderer(StoreTestCase):
    # (g) plain-language reasons + correct totals for a subtracted,
    #     budget-halted run
    def test_summary_for_subtracted_and_budget_halted_run(self):
        _run_budget_halt(store=self.store, run_id="run-b")
        text = self.store.render_run_summary("run-b")

        self.assertIn(TASK, text)
        self.assertIn("authorized and recorded", text)
        # subtracted step, with its plain-language reason
        self.assertIn("Book a flight to Boston", text)
        self.assertIn("subtracted", text)
        self.assertIn("did not explain how it serves the agreed scope", text)
        # budget halt, with its plain-language reason
        self.assertIn("BUDGET_HALTED", text)
        self.assertIn("hard limit", text)
        self.assertIn("only 0.2", text)
        # correct totals: 0.40 + 0.40 spent of the 1.00 ceiling
        self.assertIn("Total spent: 0.8 out of a budget of 1.0.", text)
        # the D-007 honesty line: no tool claimed to have run
        self.assertIn("nothing in the outside world was changed", text)

    def test_summary_for_unknown_run(self):
        self.assertIn("No receipts", self.store.render_run_summary("nope"))


class TestSupervisorIntegration(StoreTestCase):
    # (h) run_pipeline with the store on persists a clean chain
    def test_pipeline_persists_verifiable_chain_with_closeout(self):
        result = _run_mixed(store=self.store, run_id="run-h")
        self.assertEqual(result.run_id, "run-h")
        self.assertTrue(result.receipts_complete)

        records = self.store.query(run_id="run-h")
        self.assertEqual(len(records), len(result.receipts))
        self.assertEqual(records[-1]["receipt"]["stage"], "Closeout")

        ok, bad, reason = self.store.verify_chain()
        self.assertTrue(ok, reason)
        self.assertIsNone(bad)

    def test_store_off_by_default_and_behavior_unchanged(self):
        plain = _run_mixed()
        self.assertIsNone(plain.run_id)
        self.assertFalse(self.path.exists())

        stored = _run_mixed(store=self.store, run_id="run-x")
        self.assertEqual(plain.status, stored.status)
        self.assertEqual(plain.total_cost, stored.total_cost)
        self.assertEqual(
            [d["decision"] for d in plain.step_decisions],
            [d["decision"] for d in stored.step_decisions],
        )
        self.assertEqual(
            [d["decision"] for d in stored.step_decisions],
            ["EXECUTED", "SUBTRACTED", "DENIED"],
        )


if __name__ == "__main__":
    unittest.main()
