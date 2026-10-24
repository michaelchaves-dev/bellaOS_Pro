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
