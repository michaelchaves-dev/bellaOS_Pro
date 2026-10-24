# bellaOS Pro — Slice 1 Build Notes

What this is: the **Sovereign Kernel + Runtime Supervisor** for
bellaOS Pro, built locally to the owner's spec and 2026-10-23 design
revision. Pure Python, standard library only. Nothing here has been
pushed to GitHub.

## Honest evidence state

**PARTIALLY PROVEN.** A 15-test unit suite passes locally against the
specified invariants. The kernel is NOT integrated with CNS, the
router, the control plane, or any real tool; "execution" inside the
supervisor is a governed, receipted *record* (authorization + route +
budget debit), not an external side effect. This is not a production
runtime and must not be described as one.

## Layout

```text
bellaos-pro-build/
├── MODULE_REGISTRY.md   # ecosystem modules by layer, honest evidence states
├── BUILD_STATE.md       # slice log + recorded test results
├── DECISIONS.md         # decision log (D-001: LICENSE is the owner's call)
├── README_BUILD.md      # this file
├── reference/           # read-only clone of the upstream spec repo
├── bellaos_pro/
│   ├── __init__.py      # public API exports
│   ├── kernel.py        # types, authority model, intake stages, receipts
│   └── supervisor.py    # the runtime supervisor step loop + routing
└── tests/
    ├── test_kernel.py       # intake + authority invariants
    └── test_supervisor.py   # step loop: escalation, budget, subtraction, routing
```

## The design

**Intake (once per run)** — `run_intake()` in `kernel.py`:
StepZero (framing; content screened for authorization claims, which
are receipted and ignored) → ReuseCheck (registry dict or JSON file)
→ NegativeStepZero (a contract stating no problem blocks the run) →
ScopeContract validation → EvidenceLabeling (VERIFIED / INFERENCE /
UNRESOLVED; unlabeled claims default to UNRESOLVED — no unverified
promotion).

**Supervisor loop (every step)** — `Supervisor.run()` in
`supervisor.py`. Each `ProposedStep` is mediated in strict order:

1. **Injection screen** — content claiming authority ("the owner
   approved…", "permission is granted…") DENIES the step and is
   receipted. Content can never grant authority, at intake or
   mid-run.
2. **Negative Step Zero, per step** — a step that cannot state how
   it serves the scope contract (`serves_scope`) is SUBTRACTED:
   skipped, receipted, run continues.
3. **Authority re-check** — the step's capability must be *held* and
   the owner's permission dial (ALONE / ASK_FIRST / NEVER, set only
   by the owner principal via `Authority.set_permission`) must allow
   it. Unset dial fails closed: DENIED. Capability ≠ authority, in
   both directions.
4. **Approval gate** — ASK_FIRST halts the run with
   AWAITING_APPROVAL; the step never executes.
5. **Routing + budget** — `RouteTable.cheapest_capable()` picks the
   lowest-cost route whose tier suffices (a cheaper, insufficient
   route is never chosen). Cost is debited against the run budget,
   a hard ceiling: the step that would exceed it halts the run with
   BUDGET_HALTED, prior receipts intact.

**Objective hierarchy (fixed, in code order):** (1) the user's best
interest — contract + authority, hard limits; (2) logic — every
executed step traces to the contract; (3) cost efficiency —
cheapest capable route inside the ceiling. Routing is only consulted
after gates 1–2 pass; cost never outranks them.

**Receipts** — exactly one per intake stage, one per step (whatever
its outcome), one Closeout with totals; exportable as JSONL via
`receipts_path`. A run reports SUCCESS only if
`receipts_chain_complete()` verifies the chain; otherwise the kernel
refuses the label itself.

**Result** — `RunResult`: status (SUCCESS / BLOCKED / DENIED /
AWAITING_APPROVAL / BUDGET_HALTED), reasons, per-step decisions
(decision, route, cost, reason), executed/subtracted step indexes,
total cost (Decimal-exact internally), reuse hits, labeled claims,
receipts, and the completeness flag.

## Run the tests

From `~/workspace/bellaos-pro-build/`:

```sh
python3 -m unittest discover        # or add -v for per-test names
```

Recorded 2026-10-23: **15 tests, all passing** (`OK`). See
BUILD_STATE.md for the full list.

## Minimal usage

```python
from bellaos_pro import (
    Authority, PermissionLevel, Principal, ProposedStep, Route,
    ScopeContract, run_pipeline,
)

owner = Principal.owner("Michael")
authority = Authority()
authority.set_permission("read_spreadsheet", PermissionLevel.ALONE, principal=owner)

contract = ScopeContract(
    task="Summarize this week's rent roll and flag anomalies.",
    problem="The weekly rent roll takes an hour to review by hand.",
    scope="Read the rent-roll export and produce an anomaly summary.",
    output_contract="A one-page anomaly report.",
    requester="Michael",
    budget="1.00",
)
step = ProposedStep(
    capability="read_spreadsheet",
    action="Read the rent-roll export",
    serves_scope="Provides the data for the anomaly report in the output contract.",
)
result = run_pipeline(
    contract.task, contract, authority,
    steps=[step],
    held_capabilities={"read_spreadsheet"},
    routes=[Route("sheet-basic", "read_spreadsheet", 1, "0.10")],
    receipts_path="run-receipts.jsonl",
)
print(result.status, result.total_cost, result.receipts_complete)
```
