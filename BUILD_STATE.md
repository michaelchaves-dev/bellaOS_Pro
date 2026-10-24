# bellaOS Pro — Build State

Local build directory: `~/workspace/bellaos-pro-build/`
Upstream repo (`michaelchaves-dev/bellaOS_Pro`): README architecture
spec + IP_NOTICE.md only — cloned read-only into `reference/` for
reference. **Nothing has been pushed to GitHub.**

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
| Slice 1 | Sovereign Kernel + Runtime Supervisor (`bellaos_pro/`), stdlib-only Python, with unit tests | BUILT — tests PASS (below) |
| Slice 2+ | CNS / router adapters, challenge hook, owner console (L7) | NOT STARTED — owner's go required |

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

## Evidence labels (honest)

- **Slice 0: COMPLETE** as documentation. Every ecosystem module in
  the registry is labeled UNPROVEN or NOT TESTED — nothing has been
  assembled, and this file does not pretend otherwise.
- **Slice 1: PARTIALLY PROVEN.** The kernel + supervisor behave as
  specified under a 15-test local unit suite covering the invariants
  (content-cannot-grant-authority, capability ≠ authority,
  fail-closed dial, per-step subtraction, approval halt, budget halt,
  cheapest-capable routing, receipt completeness). NOT proven:
  integration with any real module (CNS, router, control plane),
  real tool execution (Slice 1 execution is a governed record —
  see DECISIONS.md D-007), performance, and any production use.

## Awaiting the owner

1. LICENSE decision (DECISIONS.md D-001).
2. Approval to push this build to a GitHub branch for review.
3. Go/no-go on Slice 2 (adapters), one slice at a time.
