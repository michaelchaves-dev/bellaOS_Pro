# bellaOS Pro — Build State

Local build directory: `~/workspace/bellaos-pro-build/`
Upstream repo (`michaelchaves-dev/bellaOS_Pro`): README architecture
spec + IP_NOTICE.md only — cloned read-only into `reference/` for
reference. Slice 0 + 1 have been pushed to the GitHub branch
`slice-0-1-sovereign-kernel` with the owner's approval. **Slice 2
and the strengthening pass are local only — nothing of them has
been pushed.**

## Design (Slice 1, per the owner's 2026-10-23 revision)

Bella is a **runtime supervisor**, not a one-pass preflight pipeline.

- **Intake (once):** StepZero framing + content injection screen →
  ReuseCheck → Negative Step Zero (no stated problem, no run) →
  ScopeContract validation → EvidenceLabeling (ternary labels;
  unlabeled claims default to UNRESOLVED).
- **Step loop (every proposed step, mediated one at a time):**
  1. Injection screen — a step claiming authority from content is
     DENIED and receipted.
  2. Negative Step Zero per step — a step that does not trace to the
     scope contract is SUBTRACTED (skipped, with reason).
  3. Authority re-check — capability held AND owner dial allows it;
     unset dial fails closed (DENIED); NEVER denies.
  4. Approval gate — ASK_FIRST halts with AWAITING_APPROVAL; the
     step does not execute.
  5. Cheapest capable route chosen from the route table and debited
     against the run budget — a HARD ceiling; exhaustion halts the
     run cleanly with BUDGET_HALTED and full receipts.
- **Objective hierarchy (fixed):** (1) user's best interest =
  contract + authority (hard limits) → (2) logic = every step traces
  to the contract → (3) cost efficiency = cheapest capable route
  inside the ceiling. Cost never outranks 1 or 2.
- **Receipts:** one per intake stage, one per step, one Closeout;
  JSONL export; SUCCESS is refused unless the chain verifies
  complete and in order.

## Slice log

| Slice | Scope | Status |
|---|---|---|
| Slice 0 | Module registry, build state, decision log | COMPLETE (this file set) |
| Slice 1 | Sovereign Kernel + Runtime Supervisor (`bellaos_pro/`), stdlib-only Python, with unit tests | BUILT — tests PASS (below); pushed to branch `slice-0-1-sovereign-kernel` |
| Slice 2 | Receipts Engine (`bellaos_pro/receipts.py`): hash-chained persistent receipt store, chain verification, query API, Decimal cost ledger, plain-language run summaries; supervisor streams receipts opt-in | BUILT LOCALLY — tests PASS (below); NOT pushed |
| Tuning pass | Proving-ground harness (`tuning/`): 30 seeded scenarios x 5 seeds + 120 fuzz runs = 270 runs, invariants A1–A9 asserted per run; found and fixed one kernel bug (see below) | COMPLETE LOCALLY — final pass 0 violations; NOT pushed |
| Strengthening pass | Owner-approved fixes for WEAK_SPOTS F-01/F-02/F-03 + items 4–6: budget hardening, owner credential binding, HMAC-keyed receipt chain + signed anchor + run registry, authority receipts + per-run dial snapshot, exception-safe ABORTED runs + locked/fsynced store appends, required_capabilities enforcement (DECISIONS D-010–D-016) | COMPLETE LOCALLY — 59 unit tests PASS, harness re-run 270 runs / 0 violations; NOT pushed |
| Slice 3+ | CNS / router adapters, challenge hook, owner console (L7) | NOT STARTED — owner's go required |

## Test results — Slice 1 (recorded 2026-10-23)

Command (from `~/workspace/bellaos-pro-build/`):

```text
python3 -m unittest discover
```

Real output (summary): **Ran 15 tests in 0.007s — OK. Result: PASS.**

All 15 tests passed:

- `test_kernel.TestContentCannotGrantAuthority`
  - test_injected_authorization_is_ignored_and_receipted
  - test_non_owner_cannot_set_permission
- `test_kernel.TestCapabilityVsAuthority`
  - test_held_capability_without_authority_is_denied
  - test_unset_permission_fails_closed
  - test_authority_without_capability_is_denied
  - test_never_permission_is_denied
- `test_kernel.TestNegativeStepZeroIntake`
  - test_no_problem_blocks_the_run
- `test_kernel.TestEvidenceAndReuse`
  - test_unlabeled_claim_defaults_to_unresolved
  - test_reuse_check_records_hit
- `test_supervisor.TestCleanFullPass`
  - test_full_pass_receipt_chain_and_jsonl
- `test_supervisor.TestApprovalGate`
  - test_ask_first_halts_without_executing
- `test_supervisor.TestMidRunEscalation`
  - test_escalation_step_denied_and_receipted
- `test_supervisor.TestBudgetCeiling`
  - test_budget_halts_at_exact_step
- `test_supervisor.TestPerStepSubtraction`
  - test_unrelated_step_subtracted
- `test_supervisor.TestCheapestCapableRouting`
  - test_cheapest_capable_route_chosen

## Test results — Slice 2 (recorded 2026-10-23)

Command (from `~/workspace/bellaos-pro-build/`):

```text
python3 -m unittest discover
```

Real output (summary): **Ran 26 tests in 0.033s — OK. Result: PASS**
(the 15 Slice 1 tests above, untouched and still passing, plus the
11 Slice 2 tests below).

- `test_receipts.TestChainVerification`
  - test_clean_chain_verifies
  - test_tampered_field_fails_at_that_index
  - test_swapped_receipts_fail
  - test_deleted_middle_receipt_fails
  - test_forged_append_fails
- `test_receipts.TestQuery`
  - test_query_filters
- `test_receipts.TestCostLedger`
  - test_ledger_reconciles_with_receipts
- `test_receipts.TestRenderer`
  - test_summary_for_subtracted_and_budget_halted_run
  - test_summary_for_unknown_run
- `test_receipts.TestSupervisorIntegration`
  - test_pipeline_persists_verifiable_chain_with_closeout
  - test_store_off_by_default_and_behavior_unchanged

## Test results — Tuning pass (recorded 2026-10-23)

Harness: `python3 -m tuning.runner` (30 scenarios x 5 seeds +
120 seeded fuzz runs = **270 runs**; every run asserted invariants
A1–A9 plus its scenario expectations; full detail in
`TUNING_REPORT.md`).

- **Pre-fix pass:** 46 violations, one root cause — the supervisor's
  injection screen scanned only `step.action`/`step.content`; a
  claim carried in `serves_scope` or `keywords` evaded it and the
  step executed, violating D-004.
- **Fix:** regression tests first
  (`TestInjectionAllSurfaces`, 2 tests, both failed pre-fix), then a
  minimal supervisor change: gate 1 scans all four text surfaces.
- **Full unit suite after the fix: Ran 28 tests — OK** (26
  pre-existing, untouched, plus the 2 regression tests).
- **Post-fix pass: 270 runs, 0 violations, 0 harness errors.**
  Simulated cheapest-capable savings on SUCCESS runs: 33.6%
  [SIMULATION — governed-record costs, not real spend].

## Test results — Strengthening pass (recorded 2026-10-23)

Owner approved the full strengthening list (WEAK_SPOTS F-01/F-02/F-03
plus items 4–6). Protocol held: test-first — the new suite
(`tests/test_strengthening.py`, 31 tests) was written first and run
red (6 failures, 22 errors) before any fix; no existing test or
assertion was weakened, deleted, or edited (all 28 pre-existing
tests pass untouched; API changes are backward-compatible
additions only).

```text
python3 -m unittest discover
Ran 59 tests — OK. Result: PASS.
```

(28 pre-existing + 31 new: TestBudgetHardening 7, TestOwnerBinding 6,
TestKeyedChain 7, TestLegacyStoreCompat 2, TestAuthorityReceipts 2,
TestExceptionSafety 3, TestRequiredCapabilities 4.)

Harness re-run after the fixes (`python3 -m tuning.runner`):

```text
runs=270 battery=150 fuzz=120 violations=0 harness_errors=0
statuses={SUCCESS: 64, DENIED: 149, AWAITING_APPROVAL: 23,
          BUDGET_HALTED: 19, BLOCKED: 15}
subtract_rate=0.199 · simulated savings 33.6% [SIMULATION]
```

Status distribution is identical to the pre-strengthening pass —
strengthening changed refusal strength, not run behavior. Decisions
recorded as D-010–D-016. Item 6 pre-check: no existing test or
harness scenario sets `required_capabilities` — enforcement changed
no prior expectation. Item 7 was a decision record only (D-016),
no code change, per the owner's call.

## Evidence labels (honest)

- **Slice 0: COMPLETE** as documentation. Every ecosystem module in
  the registry is labeled UNPROVEN or NOT TESTED — nothing has been
  assembled, and this file does not pretend otherwise.
- **Slice 1: PARTIALLY PROVEN.** The kernel + supervisor behave as
  specified under a local unit suite covering the invariants
  (content-cannot-grant-authority, capability ≠ authority,
  fail-closed dial, per-step subtraction, approval halt, budget halt,
  cheapest-capable routing, receipt completeness) — now 59 tests
  total after the strengthening pass added: contract-authoritative
  budgets with intake money validation (F-03), owner credential
  binding with a loudly-flagged unbound mode (F-01),
  exception-safe ABORTED runs, and required_capabilities
  enforcement. NOT proven: integration with any real module (CNS,
  router, control plane), real tool execution (Slice 1 execution is
  a governed record — see DECISIONS.md D-007), performance, and any
  production use. ASK_FIRST still has no resume semantics (F-12,
  owed before Slice 3).

- **Slice 2: PARTIALLY PROVEN.** The receipts engine behaves as
  specified under its local unit suite: hash chain over canonical
  JSON with a zero-hash genesis, detection of field tampering /
  reordering / mid-chain deletion / forged append at the first bad
  index, exact-match query filters, Decimal cost ledger reconciling
  with hand-summed receipts and Closeout totals, plain-language
  summaries with correct reasons and totals, and opt-in supervisor
  streaming that leaves default behavior unchanged. The
  strengthening pass closed the F-02 hole: v2 records hash the full
  record body (extra-field smuggling detected), an optional HMAC
  key makes full-store rewrites fail verification and rejects
  unkeyed downgrades, and the signed anchor + run registry detect
  suffix truncation and whole-run deletion — WHEN a key is used and
  an anchor is written and checked. Stated limits: an unkeyed store
  remains rewritable by a determined attacker (the anchor detects
  naive rewrites; it cannot prevent them); the anchor is a
  point-in-time attestation, not a live monitor. Store appends are
  now lock-serialized and fsynced, but concurrent-writer load,
  crash-mid-append recovery, performance, and any production use
  remain NOT proven.

## Awaiting the owner

1. ~~LICENSE decision (DECISIONS.md D-001).~~ Decided 2026-10-23:
   Apache License 2.0 (DECISIONS.md D-009), shipped as `LICENSE`.
2. Approval to push Slice 2 + the strengthening pass to a GitHub
   branch for review (Slice 0 + 1 already pushed to
   `slice-0-1-sovereign-kernel`).
3. Go/no-go on Slice 3 (adapters), one slice at a time.
