"""Strengthening tests (2026-10-23) — the F-01/F-02/F-03 fix pass.

Written test-first against WEAK_SPOTS.md findings:

- Item 1 (F-03): budget hardening — contract budget authoritative,
  run budget may only tighten, all money inputs validated at intake.
- Item 2 (F-01): owner binding — Authority bound to an owner secret;
  unbound mode warns loudly and never looks like bound mode.
- Item 3 (F-02): keyed receipt chain (HMAC), signed head anchor,
  run registry; hashes cover ALL record fields; legacy stores keep
  working and report keyed=False.
- Item 4: authority receipts (dial changes recorded) + per-run dial
  snapshot in the intake receipts.
- Item 5: exception-safe runs — a crash mid-step ends ABORTED with a
  complete chain; SUCCESS is impossible for that run. Store appends
  are locked + fsynced.
- Item 6: required_capabilities enforced — SUCCESS requires every
  required capability to have EXECUTED, else INCOMPLETE.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bellaos_pro import (
    Authority,
    AuthorityError,
    PermissionLevel,
    Principal,
    ProposedStep,
    Route,
    RunStatus,
    ScopeContract,
    run_pipeline,
)
from bellaos_pro.receipts import (
    ReceiptStore,
    canonical_json,
    record_hash,
    verify_chain,
)

TASK = "Summarize this week's rent roll and flag anomalies."
SECRET = "correct-horse-battery-staple"
STORE_KEY = b"unit-test-hmac-key-0123456789abcdef"


def make_contract(**over):
    base = dict(
        task=TASK,
        problem="The weekly rent roll takes an hour to review by hand.",
        scope="Read the rent-roll export and produce an anomaly summary.",
        output_contract="A one-page anomaly report.",
        requester="Michael",
    )
    base.update(over)
    return ScopeContract(**base)


def make_authority(secret=None, **levels):
    if secret is None:
        auth = Authority()
        owner = Principal.owner("Michael")
    else:
        auth = Authority(owner_secret=secret)
        owner = Principal.owner("Michael", credential=secret)
    for cap, lvl in levels.items():
        auth.set_permission(cap, lvl, principal=owner)
    return auth


STEP_SUM = ProposedStep(
    capability="summarize",
    action="Summarize the rent-roll export",
    serves_scope="Produces the anomaly summary in the output contract.",
)
ROUTES = [Route("sum-basic", "summarize", 1, "0.20")]


def scope_receipt(result):
    return next(r for r in result.receipts if r["stage"] == "ScopeContract")


# ---------------------------------------------------------------------------
# Item 1 — budget hardening (F-03)
# ---------------------------------------------------------------------------

class TestBudgetHardening(unittest.TestCase):
    def run_it(self, contract, **kw):
        kw.setdefault("steps", [STEP_SUM])
        kw.setdefault("held_capabilities", {"summarize"})
        kw.setdefault("routes", ROUTES)
        return run_pipeline(
            TASK,
            contract,
            make_authority(summarize=PermissionLevel.ALONE),
            **kw,
        )

    def test_run_budget_may_not_loosen_contract_budget(self):
        result = self.run_it(make_contract(budget="1.00"), budget="2.00")
        self.assertEqual(result.status, RunStatus.BLOCKED)
        self.assertEqual(result.halted_at, "ScopeContract")
        self.assertTrue(result.receipts_complete)
        receipt = scope_receipt(result)
        self.assertEqual(receipt["status"], "BLOCKED")
        self.assertIn("loosen", receipt["details"]["reason"])
        self.assertIn("authoritative", receipt["details"]["reason"])
        # Closeout present, and no step was mediated.
        self.assertEqual(result.receipts[-1]["stage"], "Closeout")
        self.assertEqual(result.step_decisions, [])

    def test_run_budget_may_tighten_contract_budget(self):
        steps = [STEP_SUM, STEP_SUM]
        result = self.run_it(
            make_contract(budget="5.00"), steps=steps, budget="0.30"
        )
        # Ceiling is the tightened 0.30, not the contract's 5.00:
        # step 0 executes (0.20), step 1 would exceed 0.30.
        self.assertEqual(result.status, RunStatus.BUDGET_HALTED)
        self.assertEqual(result.executed_steps, [0])
        self.assertAlmostEqual(result.total_cost, 0.20)

    def test_infinite_run_budget_blocked_at_intake(self):
        result = self.run_it(make_contract(), budget="Infinity")
        self.assertEqual(result.status, RunStatus.BLOCKED)
        self.assertEqual(result.halted_at, "ScopeContract")
        self.assertTrue(result.receipts_complete)
        self.assertEqual(result.receipts[-1]["stage"], "Closeout")

    def test_nan_contract_budget_blocked_at_intake(self):
        result = self.run_it(make_contract(budget="NaN"))
        self.assertEqual(result.status, RunStatus.BLOCKED)
        self.assertEqual(result.halted_at, "ScopeContract")
        self.assertTrue(result.receipts_complete)

    def test_negative_run_budget_blocked_at_intake(self):
        result = self.run_it(make_contract(), budget="-1.00")
        self.assertEqual(result.status, RunStatus.BLOCKED)
        self.assertEqual(result.halted_at, "ScopeContract")

    def test_negative_route_cost_blocked_at_intake(self):
        bad = [Route("sum-basic", "summarize", 1, "-0.50")]
        result = self.run_it(make_contract(), routes=bad)
        self.assertEqual(result.status, RunStatus.BLOCKED)
        self.assertEqual(result.halted_at, "ScopeContract")
        self.assertIn("sum-basic", scope_receipt(result)["details"]["reason"])

    def test_infinite_route_cost_blocked_at_intake(self):
        bad = [Route("sum-basic", "summarize", 1, "Infinity")]
        result = self.run_it(make_contract(), routes=bad)
        self.assertEqual(result.status, RunStatus.BLOCKED)
        self.assertEqual(result.halted_at, "ScopeContract")


# ---------------------------------------------------------------------------
# Item 2 — owner binding (F-01)
# ---------------------------------------------------------------------------

class TestOwnerBinding(unittest.TestCase):
    def test_forged_owner_rejected_on_bound_authority(self):
        auth = Authority(owner_secret=SECRET)
        forged = Principal.owner("Mallory")  # right role, no secret
        with self.assertRaises(AuthorityError):
            auth.set_permission(
                "summarize", PermissionLevel.ALONE, principal=forged
            )
        wrong = Principal.owner("Mallory", credential="not-the-secret")
        with self.assertRaises(AuthorityError):
            auth.set_permission(
                "summarize", PermissionLevel.ALONE, principal=wrong
            )
        self.assertIsNone(auth.level_for("summarize"))

    def test_correct_secret_works_on_bound_authority(self):
        auth = Authority(owner_secret=SECRET)
        owner = Principal.owner("Michael", credential=SECRET)
        auth.set_permission("summarize", PermissionLevel.ALONE, principal=owner)
        self.assertIs(auth.level_for("summarize"), PermissionLevel.ALONE)
        self.assertTrue(auth.owner_bound)

    def test_unbound_authority_keeps_legacy_behavior(self):
        auth = Authority()
        self.assertFalse(auth.owner_bound)
        auth.set_permission(
            "summarize",
            PermissionLevel.ALONE,
            principal=Principal.owner("Michael"),
        )
        self.assertIs(auth.level_for("summarize"), PermissionLevel.ALONE)

    def test_secret_is_never_stored_or_receipted(self):
        auth = make_authority(SECRET, summarize=PermissionLevel.ALONE)
        self.assertNotIn(SECRET, repr(vars(auth)))
        self.assertNotIn(SECRET, repr(auth.snapshot()))
        with tempfile.TemporaryDirectory() as tmp:
            store = ReceiptStore(Path(tmp) / "r.jsonl")
            run_pipeline(
                TASK,
                make_contract(),
                auth,
                steps=[STEP_SUM],
                held_capabilities={"summarize"},
                routes=ROUTES,
                receipt_store=store,
                run_id="run-secret",
            )
            self.assertNotIn(SECRET, Path(store.path).read_text())

    def test_unbound_run_carries_warning_receipt_and_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ReceiptStore(Path(tmp) / "r.jsonl")
            result = run_pipeline(
                TASK,
                make_contract(),
                make_authority(summarize=PermissionLevel.ALONE),
                steps=[STEP_SUM],
                held_capabilities={"summarize"},
                routes=ROUTES,
                receipt_store=store,
                run_id="run-unbound",
            )
            self.assertFalse(result.owner_bound)
            receipt = scope_receipt(result)
            self.assertFalse(receipt["details"]["owner_bound"])
            self.assertIn("OWNER_UNBOUND", receipt["details"]["owner_warning"])
            warnings = store.query(run_id="authority-log", stage="OwnerWarning")
            self.assertEqual(len(warnings), 1)
            self.assertEqual(warnings[0]["receipt"]["status"], "OWNER_UNBOUND")
            self.assertEqual(
                warnings[0]["receipt"]["details"]["run_id"], "run-unbound"
            )

    def test_bound_run_has_no_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ReceiptStore(Path(tmp) / "r.jsonl")
            result = run_pipeline(
                TASK,
                make_contract(),
                make_authority(SECRET, summarize=PermissionLevel.ALONE),
                steps=[STEP_SUM],
                held_capabilities={"summarize"},
                routes=ROUTES,
                receipt_store=store,
                run_id="run-bound",
            )
            self.assertTrue(result.owner_bound)
            receipt = scope_receipt(result)
            self.assertTrue(receipt["details"]["owner_bound"])
            self.assertNotIn("owner_warning", receipt["details"])
            self.assertEqual(
                store.query(run_id="authority-log", stage="OwnerWarning"), []
            )


# ---------------------------------------------------------------------------
# Item 3 — keyed chain, anchor, registry (F-02)
# ---------------------------------------------------------------------------

class KeyedStoreCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.path = Path(self._tmp.name) / "receipts.jsonl"
        self.store = ReceiptStore(self.path, hmac_key=STORE_KEY)

    def _run(self, run_id):
        return run_pipeline(
            TASK,
            make_contract(budget="5.00"),
            make_authority(summarize=PermissionLevel.ALONE),
            steps=[STEP_SUM],
            held_capabilities={"summarize"},
            routes=ROUTES,
            receipt_store=self.store,
            run_id=run_id,
        )

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


class TestKeyedChain(KeyedStoreCase):
    def test_keyed_store_verifies_and_reports_keyed(self):
        self._run("run-a")
        result = self.store.verify_store()
        self.assertTrue(result.ok, result.reason)
        self.assertTrue(result.keyed)
        ok, bad, reason = self.store.verify_chain()
        self.assertTrue(ok, reason)
        self.assertIsNone(bad)

    def test_wrong_key_fails_verification(self):
        self._run("run-a")
        other = ReceiptStore(self.path, hmac_key=b"the-wrong-key")
        ok, bad, reason = other.verify_chain()
        self.assertFalse(ok)
        self.assertFalse(other.verify_store().ok)

    def test_full_rewrite_with_recomputed_unkeyed_hashes_fails(self):
        self._run("run-a")
        records = self._lines()
        prev = "0" * 64
        for rec in records:
            rec["prev_hash"] = prev
            body = {k: v for k, v in rec.items() if k != "hash"}
            rec["hash"] = record_hash(body)  # sha256, no key — attacker's best
            prev = rec["hash"]
        self._rewrite(records)
        ok, bad, reason = self.store.verify_chain()
        self.assertFalse(ok)
        self.assertEqual(bad, 0)

    def test_suffix_truncation_detected_by_anchor(self):
        self._run("run-a")
        self.store.anchor()
        records = self._lines()
        self._rewrite(records[:-1])  # drop the Closeout record
        # The remaining prefix is a perfectly valid chain on its own…
        ok, bad, reason = self.store.verify_chain()
        self.assertTrue(ok, reason)
        # …but the signed anchor knows a record is gone.
        result = self.store.verify_store()
        self.assertFalse(result.ok)
        self.assertIn("anchor", result.reason)

    def test_deleted_run_detected_via_registry(self):
        # Unkeyed store: an attacker who deletes a whole run CAN
        # repair the chain (renumber seqs, re-link prev_hashes,
        # recompute sha256 hashes) so the chain verifies clean. Only
        # the signed anchor + run registry can catch it.
        path = Path(self._tmp.name) / "unkeyed.jsonl"
        store = ReceiptStore(path)
        for run_id in ("run-a", "run-b"):
            run_pipeline(
                TASK,
                make_contract(budget="5.00"),
                make_authority(summarize=PermissionLevel.ALONE),
                steps=[STEP_SUM],
                held_capabilities={"summarize"},
                routes=ROUTES,
                receipt_store=store,
                run_id=run_id,
            )
        store.anchor()
        records = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        kept = [r for r in records if r["run_id"] != "run-b"]
        prev = "0" * 64
        for i, rec in enumerate(kept):
            rec["seq"] = i
            rec["prev_hash"] = prev
            body = {k: v for k, v in rec.items() if k != "hash"}
            rec["hash"] = record_hash(body)
            prev = rec["hash"]
        path.write_text(
            "".join(json.dumps(r) + "\n" for r in kept),
            encoding="utf-8",
        )
        reopened = ReceiptStore(path)
        # The repaired chain verifies on its own…
        ok, bad, reason = reopened.verify_chain()
        self.assertTrue(ok, reason)
        # …but the anchor's registry knows run-b existed.
        result = reopened.verify_store()
        self.assertFalse(result.ok)
        self.assertIn("anchor", result.reason)
        self.assertIn("registry", result.reason)

    def test_smuggled_extra_field_detected(self):
        self._run("run-a")
        records = self._lines()
        records[2]["smuggled"] = "extra data the hash never covered"
        self._rewrite(records)
        ok, bad, reason = verify_chain(records, key=STORE_KEY)
        self.assertFalse(ok)
        self.assertEqual(bad, 2)
        self.assertIn("hash", reason)

    def test_key_from_env_var_name(self):
        os.environ["BELLAOS_TEST_STORE_KEY"] = "env-secret"
        try:
            path = Path(self._tmp.name) / "env.jsonl"
            store = ReceiptStore(path, hmac_key="BELLAOS_TEST_STORE_KEY")
            store.append("run-e", {"seq": 0, "stage": "StepZero",
                                   "status": "PASS", "ts": 0.0,
                                   "details": {}})
            self.assertTrue(store.verify_store().keyed)
            self.assertTrue(store.verify_chain()[0])
            self.assertNotIn("env-secret", path.read_text())
        finally:
            del os.environ["BELLAOS_TEST_STORE_KEY"]


class TestLegacyStoreCompat(unittest.TestCase):
    """Stores written by the pre-strengthening code (4-field sha256
    bodies, no version marker) must keep verifying, must report
    keyed=False, and must reject smuggled extra fields."""

    def _write_legacy(self, path):
        receipts = [
            {"seq": 0, "stage": "StepZero", "status": "PASS", "ts": 1.0,
             "details": {"task": TASK}},
            {"seq": 1, "stage": "Closeout", "status": "SUCCESS", "ts": 2.0,
             "details": {"total_cost": 0.0}},
        ]
        prev = "0" * 64
        lines = []
        for i, receipt in enumerate(receipts):
            body = {"run_id": "legacy-run", "seq": i,
                    "prev_hash": prev, "receipt": receipt}
            record = dict(body)
            record["hash"] = record_hash(body)  # legacy algorithm
            prev = record["hash"]
            lines.append(json.dumps(record))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def test_legacy_store_verifies_with_keyed_false(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.jsonl"
            self._write_legacy(path)
            store = ReceiptStore(path)
            ok, bad, reason = store.verify_chain()
            self.assertTrue(ok, reason)
            result = store.verify_store()
            self.assertTrue(result.ok, result.reason)
            self.assertFalse(result.keyed)

    def test_legacy_smuggled_extra_field_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "legacy.jsonl"
            self._write_legacy(path)
            records = [
                json.loads(line)
                for line in path.read_text().splitlines() if line.strip()
            ]
            records[0]["smuggled"] = True
            path.write_text(
                "".join(json.dumps(r) + "\n" for r in records),
                encoding="utf-8",
            )
            ok, bad, reason = ReceiptStore(path).verify_chain()
            self.assertFalse(ok)


# ---------------------------------------------------------------------------
# Item 4 — authority receipts + per-run snapshot
# ---------------------------------------------------------------------------

class TestAuthorityReceipts(unittest.TestCase):
    def test_dial_changes_recorded_with_old_and_new_levels(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ReceiptStore(Path(tmp) / "r.jsonl")
            auth = Authority()
            store.attach_authority(auth)
            owner = Principal.owner("Michael")
            auth.set_permission(
                "summarize", PermissionLevel.ASK_FIRST, principal=owner
            )
            auth.set_permission(
                "summarize", PermissionLevel.ALONE, principal=owner
            )
            changes = store.query(
                run_id="authority-log", stage="AuthorityChange"
            )
            self.assertEqual(len(changes), 2)
            first = changes[0]["receipt"]["details"]
            self.assertEqual(first["actor"], "Michael")
            self.assertEqual(first["capability"], "summarize")
            self.assertIsNone(first["old_level"])
            self.assertEqual(first["new_level"], "ASK_FIRST")
            second = changes[1]["receipt"]["details"]
            self.assertEqual(second["old_level"], "ASK_FIRST")
            self.assertEqual(second["new_level"], "ALONE")

    def test_run_snapshot_matches_dial_at_start_and_is_frozen(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ReceiptStore(Path(tmp) / "r.jsonl")
            auth = make_authority(summarize=PermissionLevel.ALONE)
            result = run_pipeline(
                TASK,
                make_contract(),
                auth,
                steps=[STEP_SUM],
                held_capabilities={"summarize"},
                routes=ROUTES,
                receipt_store=store,
                run_id="run-snap",
            )
            receipt = scope_receipt(result)
            self.assertEqual(
                receipt["details"]["dial_snapshot"],
                {"summarize": "ALONE"},
            )
            expected_hash = hashlib.sha256(
                canonical_json({"summarize": "ALONE"}).encode("utf-8")
            ).hexdigest()
            self.assertEqual(
                receipt["details"]["dial_snapshot_hash"], expected_hash
            )
            # A post-run dial change must not alter the stored snapshot.
            auth.set_permission(
                "summarize",
                PermissionLevel.NEVER,
                principal=Principal.owner("Michael"),
            )
            stored = store.query(run_id="run-snap", stage="ScopeContract")
            self.assertEqual(len(stored), 1)
            self.assertEqual(
                stored[0]["receipt"]["details"]["dial_snapshot"],
                {"summarize": "ALONE"},
            )


# ---------------------------------------------------------------------------
# Item 5 — exception-safe runs + store locking
# ---------------------------------------------------------------------------

class TestExceptionSafety(unittest.TestCase):
    def test_step_exception_aborts_with_complete_chain(self):
        with mock.patch(
            "bellaos_pro.supervisor.RouteTable.cheapest_capable",
            side_effect=RuntimeError("routing exploded"),
        ):
            result = run_pipeline(
                TASK,
                make_contract(),
                make_authority(summarize=PermissionLevel.ALONE),
                steps=[STEP_SUM, STEP_SUM],
                held_capabilities={"summarize"},
                routes=ROUTES,
            )
        self.assertEqual(result.status, RunStatus.ABORTED)
        self.assertEqual(result.halted_at, "Step:0")
        self.assertTrue(result.receipts_complete)
        self.assertEqual(result.executed_steps, [])
        step_receipt = next(
            r for r in result.receipts if r["stage"] == "Step:0"
        )
        self.assertEqual(step_receipt["status"], "ABORTED")
        self.assertEqual(
            step_receipt["details"]["error_type"], "RuntimeError"
        )
        closeout = result.receipts[-1]
        self.assertEqual(closeout["stage"], "Closeout")
        self.assertEqual(closeout["status"], "ABORTED")
        self.assertIn("RuntimeError", closeout["details"]["error"])

    def test_aborted_run_chain_verifies_in_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ReceiptStore(Path(tmp) / "r.jsonl")
            with mock.patch(
                "bellaos_pro.supervisor.RouteTable.cheapest_capable",
                side_effect=ValueError("bad route table"),
            ):
                result = run_pipeline(
                    TASK,
                    make_contract(),
                    make_authority(summarize=PermissionLevel.ALONE),
                    steps=[STEP_SUM],
                    held_capabilities={"summarize"},
                    routes=ROUTES,
                    receipt_store=store,
                    run_id="run-crash",
                )
            self.assertEqual(result.status, RunStatus.ABORTED)
            ok, bad, reason = store.verify_chain()
            self.assertTrue(ok, reason)
            records = store.query(run_id="run-crash")
            self.assertEqual(records[-1]["receipt"]["stage"], "Closeout")
            self.assertEqual(records[-1]["receipt"]["status"], "ABORTED")

    def test_store_lock_file_is_cleaned_up(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "r.jsonl"
            store = ReceiptStore(path)
            store.append("run-l", {"seq": 0, "stage": "StepZero",
                                   "status": "PASS", "ts": 0.0,
                                   "details": {}})
            self.assertFalse(Path(str(path) + ".lock").exists())
            self.assertTrue(store.verify_chain()[0])


# ---------------------------------------------------------------------------
# Item 6 — required_capabilities enforcement
# ---------------------------------------------------------------------------

class TestRequiredCapabilities(unittest.TestCase):
    def test_missing_required_capability_ends_incomplete(self):
        contract = make_contract(
            required_capabilities=["summarize", "write_report"]
        )
        result = run_pipeline(
            TASK,
            contract,
            make_authority(summarize=PermissionLevel.ALONE),
            steps=[STEP_SUM],
            held_capabilities={"summarize"},
            routes=ROUTES,
        )
        self.assertEqual(result.status, RunStatus.INCOMPLETE)
        self.assertEqual(result.executed_steps, [0])
        self.assertTrue(result.receipts_complete)
        closeout = result.receipts[-1]
        self.assertEqual(closeout["status"], "INCOMPLETE")
        self.assertEqual(
            closeout["details"]["missing_capabilities"], ["write_report"]
        )

    def test_all_required_capabilities_executed_succeeds(self):
        contract = make_contract(
            required_capabilities=["summarize", "write_report"]
        )
        auth = make_authority(
            summarize=PermissionLevel.ALONE,
            write_report=PermissionLevel.ALONE,
        )
        steps = [
            STEP_SUM,
            ProposedStep(
                capability="write_report",
                action="Write the anomaly report",
                serves_scope="Produces the deliverable in the output contract.",
            ),
        ]
        result = run_pipeline(
            TASK,
            contract,
            auth,
            steps=steps,
            held_capabilities={"summarize", "write_report"},
            routes=ROUTES + [Route("rep-basic", "write_report", 1, "0.10")],
        )
        self.assertEqual(result.status, RunStatus.SUCCESS)
        self.assertEqual(result.missing_capabilities, [])

    def test_subtracted_required_capability_is_incomplete(self):
        contract = make_contract(required_capabilities=["summarize"])
        off_contract = ProposedStep(
            capability="summarize",
            action="Book a flight to Boston",
            serves_scope="",  # no trace to the contract → subtracted
        )
        result = run_pipeline(
            TASK,
            contract,
            make_authority(summarize=PermissionLevel.ALONE),
            steps=[off_contract],
            held_capabilities={"summarize"},
            routes=ROUTES,
        )
        self.assertEqual(result.status, RunStatus.INCOMPLETE)
        self.assertEqual(result.subtracted_steps, [0])
        self.assertEqual(result.missing_capabilities, ["summarize"])

    def test_empty_required_capabilities_unaffected(self):
        result = run_pipeline(
            TASK,
            make_contract(),
            make_authority(summarize=PermissionLevel.ALONE),
            steps=[STEP_SUM],
            held_capabilities={"summarize"},
            routes=ROUTES,
        )
        self.assertEqual(result.status, RunStatus.SUCCESS)


if __name__ == "__main__":
    unittest.main()
