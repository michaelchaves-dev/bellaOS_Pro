# bellaOS Pro — Decision Log

## D-001 — LICENSE is the owner's decision (OPEN)
2026-10-23 · Status: OPEN — owner (Michael) decides.

`IP_NOTICE.md` already exists in the bellaOS_Pro repo and is the only
IP instrument in force. This build invents **no** license terms: no
LICENSE file was created, and nothing in Slice 0/1 should be read as
granting or withholding any license. When the owner picks terms, the
file lands here as a separate, approved change.

## D-002 — Local-only build until the owner approves promotion
2026-10-23 · Status: ACTIVE.

All Slice 0/1 work lives in `~/workspace/bellaos-pro-build/`. Nothing
is pushed to GitHub and no PR is opened without the owner's explicit
approval, under Roman's review — the same discipline that launched
the studio website clean.

## D-003 — Python, standard library only
2026-10-23 · Status: ACTIVE.

The kernel and supervisor use only the Python standard library: zero
dependencies to audit, pin, or be compromised through. Money math
uses `Decimal`, never binary floats.

## D-004 — Authority is set only by the owner principal, only via API
2026-10-23 · Status: ACTIVE (invariant).

The permission dial mutates exclusively through
`Authority.set_permission(..., principal=<owner>)`, which raises for
any non-owner principal. Task text, step text and tool output are
data: authorization claims found in content are receipted as
injection attempts and change nothing. A step carrying such a claim
mid-run is denied outright.

## D-005 — Supervisor shape and the objective hierarchy (owner revision)
2026-10-23 · Status: ACTIVE (owner-directed design revision).

The kernel is a runtime supervisor, not a one-pass preflight: intake
runs once, then every proposed step is mediated individually
(injection screen → per-step Negative Step Zero → authority re-check
→ approval gate → routing/budget). The objective hierarchy is fixed
and may not be reordered:

1. The user's best interest — scope contract + authority constraints
   (hard limits, never traded away).
2. Logic — every executed step traces to the contract.
3. Cost efficiency — cheapest capable route, inside the budget
   ceiling. Routing is consulted only for steps that passed 1 and 2;
   cost never outranks them.

## D-006 — Budget is a hard ceiling
2026-10-23 · Status: ACTIVE.

The run budget (contract field or run parameter) is a hard ceiling,
not a target. A step whose cheapest capable route would exceed the
remaining budget halts the run BEFORE executing, with status
BUDGET_HALTED and the full receipt chain intact.

## D-007 — Slice 1 execution is a governed record, not side effects
2026-10-23 · Status: ACTIVE (honesty constraint).

When the supervisor "executes" a step in Slice 1, it authorizes,
routes, debits and receipts it. No real tool is invoked and nothing
in the outside world changes. Real execution is wired behind these
same gates in a later slice. Nobody may describe Slice 1 as a
working runtime for real tasks.

## D-008 — Receipts: one per stage, one per step, plus Closeout
2026-10-23 · Status: ACTIVE.

Every intake stage writes exactly one receipt; every mediated step
writes exactly one receipt (including SUBTRACTED, DENIED,
AWAITING_APPROVAL and BUDGET_HALTED outcomes); every run ends with a
Closeout receipt carrying totals. Runs export JSONL. A run may report
SUCCESS only if its receipt chain verifies complete and in order —
otherwise the kernel refuses the SUCCESS label itself (fail closed).

## D-009 — LICENSE: Apache License 2.0 (decided 2026-10-23)
Owner offered "Apache 2.0 or MIT, whichever you think is best" and delegated the choice. Decided: **Apache 2.0**, recorded by Roman. Rationale: the express patent grant, and Section 6 withholds permission to use the owner's trade names and trademarks — the code is open while the bellaOS / Subtract Architect Studios marks stay protected, matching the owner's IP_NOTICE posture. The full license text ships as `LICENSE` in this repo; IP_NOTICE.md remains in force alongside it.

## D-010 — Budget ownership: the contract budget is authoritative (F-03)
2026-10-23 · Status: ACTIVE (strengthening pass, owner-approved).

The ScopeContract budget is the owner's budget. A run-level budget
parameter may only TIGHTEN it — the effective ceiling is the minimum
of the two — and a loosening attempt is refused and receipted as
BLOCKED at the intake ScopeContract stage with the reason stated.
ALL money inputs are validated at intake: contract budget, run
budget, and every route cost must be finite, non-negative Decimals.
NaN, Infinity, and negative amounts produce a clean BLOCKED (receipt
+ Closeout present), never an exception mid-loop. Tests:
`TestBudgetHardening`, 7 tests in `tests/test_strengthening.py`.

## D-011 — Owner binding: the dial requires a credential (F-01)
2026-10-23 · Status: ACTIVE (strengthening pass, owner-approved).

An `Authority` constructed with `owner_secret` is BOUND: it stores
only a random salt and a PBKDF2-HMAC-SHA256 digest (100k iterations)
of the secret — the secret itself is never stored, receipted, or
returned. `set_permission` on a bound authority requires a principal
whose credential verifies (constant-time compare); a forged owner
carrying the right role string but a wrong/absent secret raises
AuthorityError. UNBOUND authorities keep the legacy behavior but are
dev-only and must never look identical to bound ones: the run's
ScopeContract receipt carries `owner_bound` plus a prominent
OWNER_UNBOUND warning, the RunResult carries `owner_bound=False`,
and any attached receipt store gets a standalone OwnerWarning
record. Tests: `TestOwnerBinding`, 6 tests.

## D-012 — Keyed receipt chain, signed anchor, run registry (F-02)
2026-10-23 · Status: ACTIVE (strengthening pass, owner-approved).

Store records are now format v2: the record hash covers the FULL
record body (every field except `hash` itself), closing the
extra-field smuggling gap. A store opened with `hmac_key` (bytes, a
callable returning them, or the NAME of an environment variable —
the key itself is never written to disk or into any record) writes
HMAC-SHA256 hashes; verification requires the same key, and an
unkeyed record under a keyed verification FAILS (no silent
downgrade). `anchor()` writes a signed anchor {record_count,
head_hash, registry_digest} (HMAC signature when keyed) where the
registry digest covers every run_id with its record count and
per-run head hash; `verify_store()` checks chain AND anchor, so
suffix truncation and whole-run deletion — undetectable from the
chain alone — are caught. Legacy v1 stores keep verifying under
their original 4-field hash plus an exact field-set rule (an extra
field is rejected), and verification reports `keyed=False`
explicitly via `VerifyResult`. Stated limits: an anchor is a
point-in-time attestation (appends after anchoring fail
verification until re-anchored); an UNKEYED anchor's signature is
plain sha256 — it detects naive rewrites, but keying is the real
fix. Tests: `TestKeyedChain` (7) + `TestLegacyStoreCompat` (2).

## D-013 — Authority changes are receipted; runs snapshot the dial
2026-10-23 · Status: ACTIVE (strengthening pass).

Every successful `set_permission` notifies registered listeners with
{actor, capability, old_level, new_level, ts} — never any
credential. `ReceiptStore.attach_authority()` records those changes
as receipts under the run id `authority-log`; the supervisor also
attaches an attached store for the duration of each run. Every run
freezes the complete dial state into its ScopeContract receipt (the
snapshot content plus its sha256 over canonical JSON), so a run's
authority context is provable afterward and a post-run dial change
cannot alter the stored snapshot. Tests: `TestAuthorityReceipts`,
2 tests.

## D-014 — Exception-safe runs; locked, fsynced store appends
2026-10-23 · Status: ACTIVE (strengthening pass).

A crash can never look successful. Per-step mediation (and intake)
is wrapped: an unexpected exception produces an ABORTED receipt for
the step (error type + message), an ABORTED Closeout carrying the
error, and final status ABORTED (new RunStatus value); the receipt
chain stays complete and verifiable, and SUCCESS is impossible for
that run. `ReceiptStore.append` takes an O_CREAT|O_EXCL lockfile
(retry/timeout ~5s, always cleaned up by its creator), re-scans the
chain tail under the lock, and flush+fsyncs before returning.
Residual, stated plainly: a writer killed mid-append can leave a
stale lockfile (removed deliberately by an operator, never
silently) and crash-mid-append recovery is still untested — F-08 is
partially, not fully, addressed. Tests: `TestExceptionSafety`,
3 tests.

## D-015 — required_capabilities is enforced (owner decision)
2026-10-23 · Status: ACTIVE (owner decided: ENFORCE).

If `ScopeContract.required_capabilities` is non-empty, a run may
end SUCCESS only if every required capability was EXECUTED at least
once. Otherwise the final status is INCOMPLETE (new RunStatus
value) with the missing capabilities named in the Closeout receipt
and on `RunResult.missing_capabilities`. A required capability that
was subtracted, denied, or never proposed counts as missing. Runs
with empty required_capabilities are unaffected. Pre-implementation
check (recorded): no existing test or harness scenario sets
required_capabilities, so no prior expectation was changed. Tests:
`TestRequiredCapabilities`, 4 tests.

## D-016 — Injection screen scope: a tripwire, not a semantic wall
2026-10-23 · Status: ACTIVE (owner decision — record only, no code
change in this pass).

The injection screen is a pattern tripwire over all four text
surfaces (action, content, serves_scope, keywords). Semantic /
paraphrase screening is DEFERRED to L6 (RelAI). The primary wall is
authority separation: content cannot grant authority whatever words
it uses, so a paraphrase that evades the pattern list still faces
the permission dial, the held-capability check, and the budget.
The pattern list is a known, accepted open flank (WEAK_SPOTS
F-09/F-10) — recorded here so nobody later mistakes the tripwire
for a solved problem.
