"""bellaOS Pro — the Receipts Engine (Slice 2).

L1 (Truth & Evidence) made durable: a persistent, tamper-evident
store for the receipts the Sovereign Kernel already emits.

Format — one store file, JSON Lines, append-only. Each line is one
stored record:

    {
      "run_id":    "<id of the run the receipt belongs to>",
      "seq":       <global store sequence, 0-based, contiguous>,
      "prev_hash": "<sha256 of the previous record, or ZERO_HASH>",
      "receipt":   { ... the receipt exactly as the kernel emitted it ... },
      "hash":      "<sha256 of the canonical record body>"
    }

The record body is {"run_id", "seq", "prev_hash", "receipt"}; the
hash is sha256 over its canonical serialization (JSON, sorted keys,
stable separators) — so the hash covers the prev_hash, chaining every
record to all history before it. The first record in a store (the
genesis record) uses ZERO_HASH as its prev_hash.

Because each hash covers its own contents and points at the previous
record's hash, the chain detects — at the first bad index — a field
tampered after writing, two records reordered, a record deleted
mid-chain, and a forged record appended with a wrong prev_hash.
Deleting a *suffix* of the chain is not detectable from the chain
alone (any prefix of a valid chain is valid); the signed head anchor
added in the strengthening pass (see below) covers exactly that.

What lives here:

- ``ReceiptStore`` — append (live, via the kernel's receipt sink, or
  in bulk), read, query, verify, cost ledger, plain-language summary.
- ``verify_chain(records)`` — the standalone chain checker.
- ``cost_ledger`` — totals per run / capability / route, summed
  from EXECUTED step receipts in Decimal (never float accumulation),
  reconciling exactly with the receipts and with each run's Closeout
  total.
- ``render_run_summary(run_id)`` — the owner's plain-language view,
  the seed of the L7 console. Honesty rule (DECISIONS.md D-007):
  Slice 1/2 "execution" is a governed record — the renderer says
  "authorized and recorded", never that a tool ran in the world.

Strengthening pass (2026-10-23, F-02): records written now carry
``"v": 2`` and their hash covers the FULL record body (every field
except ``hash`` itself), closing the extra-field smuggling gap. A
store opened with ``hmac_key`` writes keyed records whose hashes are
HMAC-SHA256; verification then requires the same key and rejects
unkeyed records outright (no silent downgrade). ``anchor()`` writes
a signed head anchor {record_count, head_hash, registry_digest} and
``verify_store()`` checks chain + anchor, so suffix truncation and
whole-run deletion — undetectable from the chain alone — are caught.
Legacy (v1) records keep verifying under their original 4-field
hash and an exact field-set rule; verification reports ``keyed``
explicitly. Appends are serialized with a lockfile and fsynced
before returning (item 5).

Standard library only (DECISIONS.md D-003).
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from .kernel import OWNER_UNBOUND_WARNING

__all__ = [
    "ZERO_HASH",
    "ReceiptStore",
    "VerifyResult",
    "canonical_json",
    "record_hash",
    "verify_chain",
]

ZERO_HASH = "0" * 64

_BODY_FIELDS = ("run_id", "seq", "prev_hash", "receipt")


# ---------------------------------------------------------------------------
# Canonical serialization + hashing
# ---------------------------------------------------------------------------

def canonical_json(obj) -> str:
    """Canonical form: sorted keys, stable separators, ASCII-safe.

    The same logical record always serializes to the same bytes, so a
    hash computed at write time can be recomputed at verify time.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def record_hash(body: dict, key: "bytes | None" = None) -> str:
    """Hash a record body (the record minus its ``hash`` field).

    With ``key``: HMAC-SHA256 under the key. Without: plain sha256
    over the canonical serialization. For legacy (v1) bodies the body
    is exactly {"run_id", "seq", "prev_hash", "receipt"} — prev_hash
    included, which is what makes it a chain — and the result is
    bit-identical to the pre-strengthening algorithm. For v2 bodies
    the caller passes every field except ``hash``, so the hash covers
    ALL record fields and any smuggled extra field breaks it."""
    data = canonical_json(body).encode("utf-8")
    if key is not None:
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


def _dec(value) -> Decimal:
    """Receipt money values arrive as floats/ints/strings; go through
    str() so Decimal sees the value a human reads (0.1, not
    0.1000000000000000055...)."""
    return Decimal(str(value))


def _fmt(value: Decimal) -> str:
    return format(value, "f")


# ---------------------------------------------------------------------------
# Chain verification
# ---------------------------------------------------------------------------

def verify_chain(
    records: list[dict], key: "bytes | None" = None
) -> "tuple[bool, int | None, str]":
    """Verify a list of stored records as one hash chain.

    Returns ``(ok, first_bad_index_or_None, reason)``. Checks, in
    order per record: required fields present; ``seq`` equals the
    record's position (contiguity — catches deletion, insertion and
    reordering); ``prev_hash`` links to the previous record's hash
    (catches a forged append); recomputed ``hash`` matches the stored
    one (catches any field tampered after writing).

    Record versions: v2 records (written by the strengthened store)
    are hashed over their FULL body — every field except ``hash`` —
    so a smuggled extra field breaks the hash. Keyed v2 records
    require ``key``: without it, or with the wrong key, verification
    fails; and when ``key`` is supplied, an unkeyed record fails too
    (a downgrade is a failure, never a fallback). Legacy v1 records
    verify under their original 4-field hash, but must carry EXACTLY
    the legacy field set — an extra field on a v1 record is rejected
    even though its hash cannot cover it.
    """
    prev_hash = ZERO_HASH
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            return False, i, f"record at index {i} is not an object"
        missing = [f for f in _BODY_FIELDS + ("hash",) if f not in rec]
        if missing:
            return (
                False,
                i,
                f"record at index {i} is missing field(s): "
                + ", ".join(missing),
            )
        if rec["seq"] != i:
            return (
                False,
                i,
                f"sequence mismatch at index {i}: expected seq {i}, "
                f"found {rec['seq']!r} — a receipt may have been "
                "deleted, inserted, or reordered",
            )
        if rec["prev_hash"] != prev_hash:
            return (
                False,
                i,
                f"prev_hash mismatch at index {i}: the record does "
                "not point at the previous record's hash — a receipt "
                "may have been deleted or a forged record appended",
            )
        if rec.get("v", 1) >= 2:
            body = {k: v for k, v in rec.items() if k != "hash"}
            if rec.get("keyed"):
                if key is None:
                    return (
                        False,
                        i,
                        f"record at index {i} is keyed (HMAC) and "
                        "cannot be verified without the store key",
                    )
                expected = record_hash(body, key=key)
            else:
                if key is not None:
                    return (
                        False,
                        i,
                        f"record at index {i} is not keyed but a key "
                        "was supplied — possible downgrade to unkeyed "
                        "hashing; refused",
                    )
                expected = record_hash(body)
            if expected != rec["hash"]:
                return (
                    False,
                    i,
                    f"hash mismatch at index {i}: the stored contents "
                    "were altered after writing (recomputed hash differs)",
                )
        else:
            extra = sorted(set(rec) - set(_BODY_FIELDS) - {"hash"})
            if extra:
                return (
                    False,
                    i,
                    f"record at index {i} carries unexpected field(s): "
                    + ", ".join(extra)
                    + " — legacy records must contain exactly the "
                    "legacy field set",
                )
            if key is not None:
                return (
                    False,
                    i,
                    f"record at index {i} is a legacy unkeyed record "
                    "but a key was supplied — possible downgrade; refused",
                )
            body = {f: rec[f] for f in _BODY_FIELDS}
            if record_hash(body) != rec["hash"]:
                return (
                    False,
                    i,
                    f"hash mismatch at index {i}: the stored contents "
                    "were altered after writing (recomputed hash differs)",
                )
        prev_hash = rec["hash"]
    return (
        True,
        None,
        f"chain verified: {len(records)} record(s), sequence, links "
        "and hashes intact",
    )


@dataclass
class VerifyResult:
    """Full store verification outcome (chain + signed anchor).

    ``keyed`` is reported explicitly — a legacy unkeyed store that
    verifies says keyed=False, never silently posing as a keyed one."""

    ok: bool
    keyed: bool
    reason: str
    bad_index: "int | None" = None
    record_count: int = 0
    anchor_checked: bool = False


# ---------------------------------------------------------------------------
# The store
# ---------------------------------------------------------------------------

class ReceiptStore:
    """Append-only, hash-chained JSONL receipt store.

    The parent directory of ``path`` must exist. Appending resumes
    the chain from the file's current tail (re-scanned under the
    append lock on every write); integrity is never assumed — call
    :meth:`verify_chain` or :meth:`verify_store` to check the whole
    store.

    ``hmac_key`` (optional) keys the chain: bytes are used directly,
    a str is the NAME of an environment variable holding the key, and
    a callable is called to produce it. The key is kept only in
    memory — it is never written to disk or into any record.
    """

    def __init__(self, path: "str | Path", *, hmac_key=None) -> None:
        self.path = Path(path)
        self._key = self._resolve_key(hmac_key)
        self._next_seq, self._last_hash = self._scan_tail()

    @staticmethod
    def _resolve_key(hmac_key) -> "bytes | None":
        if hmac_key is None:
            return None
        if callable(hmac_key):
            hmac_key = hmac_key()
        if isinstance(hmac_key, str):
            # A str is an environment-variable NAME, never the key
            # itself — keys do not travel through call sites as data.
            if hmac_key not in os.environ:
                raise ValueError(
                    f"hmac_key names environment variable "
                    f"{hmac_key!r}, which is not set"
                )
            return os.environ[hmac_key].encode("utf-8")
        return bytes(hmac_key)

    # -- writing -----------------------------------------------------------

    def _scan_tail(self) -> "tuple[int, str]":
        if not self.path.exists():
            return 0, ZERO_HASH
        last = None
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = json.loads(line)
        if last is None:
            return 0, ZERO_HASH
        return int(last["seq"]) + 1, str(last["hash"])

    @contextmanager
    def _locked(self):
        """Serialize writers with an O_CREAT|O_EXCL lockfile.

        Retries for up to ~5 seconds, then raises TimeoutError. The
        lockfile is always removed by its creator. (A writer killed
        mid-append can leave a stale lockfile behind; deleting it is
        a deliberate operator act, never done silently here.)"""
        lock_path = str(self.path) + ".lock"
        fd = None
        deadline = time.monotonic() + 5.0
        while fd is None:
            try:
                fd = os.open(
                    lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                )
            except FileExistsError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"timed out waiting for receipt store lock: "
                        f"{lock_path}"
                    )
                time.sleep(0.02)
        try:
            yield
        finally:
            os.close(fd)
            try:
                os.unlink(lock_path)
            except FileNotFoundError:
                pass

    def append(self, run_id: str, receipt: dict) -> dict:
        """Freeze one kernel receipt into the chain and persist it.

        The receipt is deep-copied (later mutation of the emitter's
        dict cannot rewrite history) and stored with the next global
        sequence number, the previous record's hash, and its own
        hash. New records are format v2: the hash covers the FULL
        record body, and is HMAC-SHA256 when the store is keyed.
        The write is lock-serialized and flush+fsynced before this
        returns, so a completed append survives a crash. Returns the
        stored record.
        """
        with self._locked():
            # Re-scan under the lock: another writer may have
            # appended since this store object was constructed.
            self._next_seq, self._last_hash = self._scan_tail()
            body = {
                "run_id": str(run_id),
                "seq": self._next_seq,
                "prev_hash": self._last_hash,
                "receipt": copy.deepcopy(receipt),
                "v": 2,
                "keyed": self._key is not None,
            }
            record = dict(body)
            record["hash"] = record_hash(body, key=self._key)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(canonical_json(record) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._next_seq += 1
            self._last_hash = record["hash"]
            return record

    def append_run(self, run_id: str, receipts) -> list[dict]:
        """Append a whole run's receipts, in emission order."""
        return [self.append(run_id, r) for r in receipts]

    # -- reading -------------------------------------------------------------

    def records(self) -> list[dict]:
        """All stored records, in chain order (re-read from disk)."""
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def verify_chain(self) -> "tuple[bool, int | None, str]":
        """Verify the entire store as one hash chain (with this
        store's key, if it was opened with one)."""
        return verify_chain(self.records(), key=self._key)

    # -- anchor + run registry (F-02) -------------------------------------

    def _anchor_path(self) -> Path:
        return Path(str(self.path) + ".anchor")

    @staticmethod
    def _registry(records: list[dict]) -> dict:
        """The run registry: every run_id with its record count and
        per-run head hash. A whole run deleted from the store changes
        this structure — and therefore its digest."""
        registry: dict[str, dict] = {}
        for rec in records:
            entry = registry.setdefault(
                rec["run_id"], {"count": 0, "head_hash": None}
            )
            entry["count"] += 1
            entry["head_hash"] = rec["hash"]
        return registry

    def _sign(self, payload: dict) -> str:
        data = canonical_json(payload).encode("utf-8")
        if self._key is not None:
            return hmac.new(self._key, data, hashlib.sha256).hexdigest()
        return hashlib.sha256(data).hexdigest()

    def anchor(self) -> dict:
        """Write/update the signed head anchor for the store's
        current state: {record_count, head_hash, registry_digest}
        plus an HMAC signature over that payload (plain sha256 when
        the store is unkeyed — tamper-evident, but forgeable by
        anyone; ``keyed`` in the anchor says which).

        Refuses to anchor a chain that does not verify. The anchor is
        a point-in-time attestation: appends after anchoring make
        verify_store report a mismatch until anchor() is called
        again."""
        records = self.records()
        ok, _, reason = verify_chain(records, key=self._key)
        if not ok:
            raise ValueError(
                f"refusing to anchor a broken chain: {reason}"
            )
        payload = {
            "record_count": len(records),
            "head_hash": records[-1]["hash"] if records else ZERO_HASH,
            "registry_digest": hashlib.sha256(
                canonical_json(self._registry(records)).encode("utf-8")
            ).hexdigest(),
        }
        doc = dict(payload)
        doc["keyed"] = self._key is not None
        doc["signature"] = self._sign(payload)
        with self._locked():
            with self._anchor_path().open("w", encoding="utf-8") as fh:
                fh.write(canonical_json(doc) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
        return doc

    def verify_store(self) -> VerifyResult:
        """Verify the chain AND the signed anchor.

        The chain alone cannot detect suffix truncation or deletion
        of a trailing run (any prefix of a valid chain is valid);
        the anchor can: record_count, head_hash and the run-registry
        digest must all match the anchored state, and the anchor's
        signature must verify. ``keyed`` is reported explicitly."""
        records = self.records()
        keyed = (
            any(bool(rec.get("keyed")) for rec in records)
            if records
            else self._key is not None
        )
        ok, bad, reason = verify_chain(records, key=self._key)
        if not ok:
            return VerifyResult(
                ok=False,
                keyed=keyed,
                reason=reason,
                bad_index=bad,
                record_count=len(records),
                anchor_checked=False,
            )
        anchor_path = self._anchor_path()
        if not anchor_path.exists():
            return VerifyResult(
                ok=True,
                keyed=keyed,
                reason=(
                    reason
                    + "; no anchor present — suffix truncation is "
                    "not detectable without one (call anchor())"
                ),
                record_count=len(records),
                anchor_checked=False,
            )
        try:
            doc = json.loads(anchor_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return VerifyResult(
                ok=False,
                keyed=keyed,
                reason=f"anchor is unreadable: {exc}",
                record_count=len(records),
                anchor_checked=True,
            )
        payload = {
            "record_count": doc.get("record_count"),
            "head_hash": doc.get("head_hash"),
            "registry_digest": doc.get("registry_digest"),
        }
        if doc.get("keyed") and self._key is None:
            return VerifyResult(
                ok=False,
                keyed=keyed,
                reason=(
                    "anchor is keyed but this store was opened "
                    "without the key; the anchor cannot be verified"
                ),
                record_count=len(records),
                anchor_checked=True,
            )
        expected_sig = (
            self._sign(payload)
            if doc.get("keyed")
            else hashlib.sha256(
                canonical_json(payload).encode("utf-8")
            ).hexdigest()
        )
        if not hmac.compare_digest(
            str(doc.get("signature")), expected_sig
        ):
            return VerifyResult(
                ok=False,
                keyed=keyed,
                reason=(
                    "anchor signature mismatch — the anchor was "
                    "altered, or the wrong key was used"
                ),
                record_count=len(records),
                anchor_checked=True,
            )
        problems = []
        if doc.get("record_count") != len(records):
            problems.append(
                f"record_count: anchor attests "
                f"{doc.get('record_count')}, store holds "
                f"{len(records)} — records were added or removed "
                "after anchoring (suffix truncation or a deleted run)"
            )
        head = records[-1]["hash"] if records else ZERO_HASH
        if doc.get("head_hash") != head:
            problems.append(
                "head_hash: the chain's head differs from the "
                "anchored head"
            )
        current_digest = hashlib.sha256(
            canonical_json(self._registry(records)).encode("utf-8")
        ).hexdigest()
        if doc.get("registry_digest") != current_digest:
            problems.append(
                "registry_digest: the set of runs, a run's length, "
                "or a run's head hash differs from the anchored "
                "registry — a run was deleted or altered"
            )
        if problems:
            return VerifyResult(
                ok=False,
                keyed=keyed,
                reason="anchor check failed: " + "; ".join(problems),
                record_count=len(records),
                anchor_checked=True,
            )
        return VerifyResult(
            ok=True,
            keyed=keyed,
            reason=(
                f"chain and anchor verified: {len(records)} "
                "record(s) match the signed anchor"
            ),
            record_count=len(records),
            anchor_checked=True,
        )

    # -- authority log (item 4 + OWNER_UNBOUND warnings) -------------------

    def record_dial_change(self, change: dict) -> dict:
        """Append one dial-change record (Authority listener shape):
        actor, capability, old level, new level. The change dict
        never carries any credential — the Authority builds it that
        way — and nothing secret is written here."""
        seq = len(self.query(run_id="authority-log", stage="AuthorityChange"))
        receipt = {
            "seq": seq,
            "stage": "AuthorityChange",
            "status": "SET",
            "ts": time.time(),
            "details": {
                "actor": change.get("actor"),
                "capability": change.get("capability"),
                "old_level": change.get("old_level"),
                "new_level": change.get("new_level"),
            },
        }
        return self.append("authority-log", receipt)

    def attach_authority(self, authority) -> bool:
        """Record this authority's future dial changes into the
        store. Returns True if newly attached."""
        return authority.add_change_listener(self.record_dial_change)

    def detach_authority(self, authority) -> bool:
        return authority.remove_change_listener(self.record_dial_change)

    def record_owner_warning(self, for_run_id) -> dict:
        """Append the standalone OWNER_UNBOUND warning record for a
        run executed under an unbound Authority (F-01). Kept under
        the separate ``authority-log`` run so a run's own receipt
        chain is never altered."""
        seq = len(self.query(run_id="authority-log", stage="OwnerWarning"))
        receipt = {
            "seq": seq,
            "stage": "OwnerWarning",
            "status": "OWNER_UNBOUND",
            "ts": time.time(),
            "details": {
                "run_id": for_run_id,
                "warning": OWNER_UNBOUND_WARNING,
            },
        }
        return self.append("authority-log", receipt)

    # -- query ---------------------------------------------------------------

    def query(
        self,
        *,
        run_id: "str | None" = None,
        stage: "str | None" = None,
        decision: "str | None" = None,
        capability: "str | None" = None,
    ) -> list[dict]:
        """Return the stored records matching ALL given filters.

        ``stage`` matches the receipt's stage (e.g. "StepZero",
        "Step:2", "Closeout"). ``decision`` and ``capability`` match
        the receipt's details (present on step receipts: EXECUTED,
        SUBTRACTED, DENIED, AWAITING_APPROVAL, BUDGET_HALTED).
        Records are the full stored dicts (run_id, seq, hashes, and
        the receipt itself).
        """
        out = []
        for rec in self.records():
            receipt = rec["receipt"]
            details = receipt.get("details") or {}
            if run_id is not None and rec["run_id"] != run_id:
                continue
            if stage is not None and receipt.get("stage") != stage:
                continue
            if decision is not None and details.get("decision") != decision:
                continue
            if capability is not None and details.get("capability") != capability:
                continue
            out.append(rec)
        return out

    # -- cost ledger -----------------------------------------------------------

    def cost_ledger(self) -> dict:
        """Aggregate spend from EXECUTED step receipts.

        Only executed steps are ever charged (subtracted, denied,
        approval-halted and budget-halted steps all carry cost 0 and
        are not executed records). Sums are Decimal, built from the
        receipt values exactly as stored, so the ledger reconciles
        to the cent with a hand sum of the receipts — and with each
        run's Closeout ``total_cost``.
        """
        per_run: dict[str, Decimal] = {}
        per_capability: dict[str, Decimal] = {}
        per_route: dict[str, Decimal] = {}
        total = Decimal("0")
        for rec in self.records():
            receipt = rec["receipt"]
            if receipt.get("status") != "EXECUTED":
                continue
            details = receipt.get("details") or {}
            cost = _dec(details.get("cost", 0))
            run_id = rec["run_id"]
            per_run[run_id] = per_run.get(run_id, Decimal("0")) + cost
            capability = details.get("capability")
            if capability is not None:
                per_capability[capability] = (
                    per_capability.get(capability, Decimal("0")) + cost
                )
            route = details.get("route")
            if route is not None:
                per_route[route] = per_route.get(route, Decimal("0")) + cost
            total += cost
        return {
            "per_run": per_run,
            "per_capability": per_capability,
            "per_route": per_route,
            "total": total,
        }

    # -- plain-language rendering ----------------------------------------------

    def render_run_summary(self, run_id: str) -> str:
        """Owner-readable summary of one run, from its receipts alone.

        Plain sentences, totals that reconcile with the cost ledger,
        and the D-007 honesty rule throughout: steps are "authorized
        and recorded" — no tool is claimed to have run in the world.
        """
        run_records = [r for r in self.records() if r["run_id"] == run_id]
        if not run_records:
            return f"No receipts are stored for run '{run_id}'."

        by_stage = {}
        for rec in run_records:
            by_stage.setdefault(rec["receipt"].get("stage"), []).append(rec)

        def details_of(stage):
            recs = by_stage.get(stage) or []
            return (recs[0]["receipt"].get("details") or {}) if recs else {}

        lines = [f"Run summary — {run_id}"]

        stepzero = details_of("StepZero")
        if stepzero.get("task"):
            lines.append(f"Asked to do: {stepzero['task']}")
        if stepzero.get("requester"):
            lines.append(f"Requested by: {stepzero['requester']}")
        nsz = details_of("NegativeStepZero")
        if nsz.get("problem"):
            lines.append(f"Problem it set out to solve: {nsz['problem']}")
        contract = details_of("ScopeContract")
        if contract.get("scope"):
            lines.append(f"Agreed scope: {contract['scope']}")
        if contract.get("output_contract"):
            lines.append(f"Promised output: {contract['output_contract']}")

        # Intake stops (a blocked run has no step receipts).
        for rec in run_records:
            receipt = rec["receipt"]
            if receipt.get("status") == "BLOCKED":
                reason = (receipt.get("details") or {}).get("reason", "")
                lines.append(
                    f"The run was stopped during intake at "
                    f"{receipt.get('stage')}: {reason}"
                )

        # Steps, in the order Bella mediated them.
        step_records = [
            r
            for r in run_records
            if str(r["receipt"].get("stage", "")).startswith("Step:")
        ]
        if step_records:
            lines.append("What happened, step by step:")
            for rec in step_records:
                lines.append("  " + _render_step(rec["receipt"]))

        # Totals — from the ledger, so the summary and the books agree.
        ledger = self.cost_ledger()
        spent = ledger["per_run"].get(run_id, Decimal("0"))
        budget = self._run_budget(run_records, contract)
        total_line = f"Total spent: {_fmt(spent)}"
        if budget is not None:
            total_line += f" out of a budget of {_fmt(budget)}"
        lines.append(total_line + ".")

        closeout = details_of("Closeout")
        status = None
        for rec in run_records:
            if rec["receipt"].get("stage") == "Closeout":
                status = rec["receipt"].get("status")
        gloss = {
            "SUCCESS": "completed successfully",
            "BLOCKED": "blocked during intake, before any step ran",
            "DENIED": "stopped because a step was refused",
            "AWAITING_APPROVAL": "waiting for the owner's approval",
            "BUDGET_HALTED": "halted at the budget limit, receipts intact",
            "ABORTED": "aborted by an unexpected error; the run did not complete and is not a success",
            "INCOMPLETE": "finished without executing every capability the contract required",
        }.get(status, status or "unknown")
        lines.append(f"Final status: {status} — {gloss}.")
        lines.append(
            "Note: \"authorized and recorded\" means Bella approved "
            "the step, chose its route, and charged it in these "
            "records. No outside tool is wired in yet, so nothing in "
            "the outside world was changed by this run."
        )
        return "\n".join(lines)

    @staticmethod
    def _run_budget(run_records, contract_details) -> "Decimal | None":
        budget = None
        for rec in run_records:
            details = rec["receipt"].get("details") or {}
            if details.get("budget_ceiling") is not None:
                budget = _dec(details["budget_ceiling"])
        if budget is None and contract_details.get("budget") is not None:
            budget = _dec(contract_details["budget"])
        return budget


# ---------------------------------------------------------------------------
# Plain-language step sentences
# ---------------------------------------------------------------------------

def _render_step(receipt: dict) -> str:
    details = receipt.get("details") or {}
    n = int(details.get("index", 0)) + 1
    action = details.get("action", "(unnamed step)")
    capability = details.get("capability", "")
    status = receipt.get("status")
    reason = details.get("reason", "")

    if status == "EXECUTED":
        return (
            f"Step {n}: {action} — authorized and recorded via "
            f"route '{details.get('route')}' at a cost of "
            f"{_fmt(_dec(details.get('cost', 0)))}."
        )
    if status == "SUBTRACTED":
        if "keywords" in reason:
            why = "its topics fell outside the agreed scope"
        else:
            why = "it did not explain how it serves the agreed scope"
        return (
            f"Step {n}: {action} — skipped (subtracted) before "
            f"running, because {why}. The per-step logic check "
            "removed it; nothing was spent on it."
        )
    if status == "DENIED":
        if "attempted to grant authority" in reason or "Content attempted" in reason:
            why = (
                "the step's own text tried to claim authorization, "
                "and claims inside content are never accepted as "
                "permission"
            )
        elif "is not held" in reason:
            why = f"the run does not hold the capability '{capability}'"
        elif "No authority set" in reason:
            why = (
                f"no permission has been set for '{capability}', "
                "and an unset permission is refused by default"
            )
        elif "NEVER" in reason:
            why = f"the owner's permission dial is set to NEVER for '{capability}'"
        elif "No capable route" in reason:
            why = (
                f"no route able to perform '{capability}' at the "
                "required level was available"
            )
        else:
            why = reason
        return (
            f"Step {n}: {action} — refused (denied), and the run "
            f"stopped here, because {why}."
        )
    if status == "AWAITING_APPROVAL":
        return (
            f"Step {n}: {action} — paused for approval. "
            f"'{capability}' is set to ask-first on the owner's "
            "dial, so the step was not run and the run is waiting "
            "for the owner."
        )
    if status == "BUDGET_HALTED":
        ceiling = _dec(details.get("budget_ceiling", 0))
        spent_before = _dec(details.get("budget_spent", 0))
        route_cost = _dec(details.get("route_cost", 0))
        remaining = ceiling - spent_before
        return (
            f"Step {n}: {action} — stopped before running. Its "
            f"route '{details.get('route')}' would cost "
            f"{_fmt(route_cost)}, but only {_fmt(remaining)} of "
            f"the {_fmt(ceiling)} budget remained. The budget is "
            "a hard limit, so the run halted here."
        )
    return f"Step {n}: {action} — outcome {status}. {reason}"
