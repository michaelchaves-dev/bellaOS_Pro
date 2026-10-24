"""bellaOS Pro — the Runtime Supervisor (Slice 1, owner revision).

Bella is not a one-pass preflight pipeline. She is a runtime
supervisor: after intake, she mediates EVERY proposed step and tool
call of a run, one at a time, before it may execute.

For each proposed step, in this order:

1. **Injection screen** — if the step's content claims authority
   ("the owner approved this", "I grant permission", ...), the step is
   DENIED and the attempt is receipted. Content can never grant
   authority, at intake or mid-run (NO SILENT ESCALATION).
2. **Negative Step Zero, per step** — a step that does not trace to
   the scope contract is SUBTRACTED: skipped, with a receipt stating
   why. Subtraction is not failure; it is the logic gate doing its job.
3. **Authority re-check** — capability and authority are re-verified
   for THIS step: capability must be held AND the owner's permission
   dial must allow it. Unset dial = DENIED (fail closed). NEVER =
   DENIED. The dial is only ever set by the owner principal through
   the Authority API, never from content.
4. **Approval gate** — an ASK_FIRST capability halts the step (and
   the run) with AWAITING_APPROVAL. The step does not execute.
5. **Routing + budget** — the cheapest capable route is chosen from
   the route table (lowest cost among routes whose capability tier
   suffices) and its cost debited against the run budget. The budget
   is a HARD ceiling: a step that would exceed it halts the run
   cleanly with BUDGET_HALTED and full receipts.

Objective hierarchy (never reordered):

1. **The user's best interest** — the scope contract + authority
   constraints. Hard limits; never traded away.
2. **Logic** — every executed step must trace to the contract
   (per-step Negative Step Zero). Enforced before routing.
3. **Cost efficiency** — cheapest capable route per step, inside the
   budget ceiling. Cost never outranks 1 or 2: routing is only ever
   consulted for a step that already passed the gates above.

Execution in Slice 1 is a *governed execution record*: the supervisor
authorizes, routes, debits and receipts the step. Real tool side
effects are wired behind these same gates in a later slice; nothing
here touches the outside world (NO PRODUCTION CLAIM FROM A SPEC
ALONE — and none from a kernel record either).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from decimal import Decimal

from .kernel import (
    Authority,
    PermissionLevel,
    ReceiptLog,
    RunStatus,
    ScopeContract,
    receipts_chain_complete,
    run_intake,
    scan_for_injection,
)

__all__ = [
    "ProposedStep",
    "Route",
    "RouteTable",
    "RunResult",
    "Supervisor",
    "run_pipeline",
]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@dataclass
class Route:
    """One way to perform a capability: a tier (capability level) and
    a cost. Costs are Decimal — money math does not get float drift."""

    name: str
    capability: str
    tier: int
    cost: "Decimal | float | int | str"

    def __post_init__(self) -> None:
        if not isinstance(self.cost, Decimal):
            self.cost = Decimal(str(self.cost))


class RouteTable:
    def __init__(self, routes: "list[Route] | None" = None) -> None:
        self.routes: list[Route] = list(routes or [])

    def cheapest_capable(self, capability: str, min_tier: int) -> "Route | None":
        """Lowest-cost route whose tier suffices for the step.

        A cheaper route with an insufficient tier is NOT capable and
        is never chosen; among sufficient routes, cost decides, then
        lower tier, then name (deterministic)."""
        candidates = [
            r
            for r in self.routes
            if r.capability == capability and r.tier >= min_tier
        ]
        if not candidates:
            return None
        return min(candidates, key=lambda r: (r.cost, r.tier, r.name))


# ---------------------------------------------------------------------------
# Proposed steps and the run result
# ---------------------------------------------------------------------------

@dataclass
class ProposedStep:
    """A step/tool call proposed to the supervisor mid-run.

    ``serves_scope`` is the step's logic link: how it serves the scope
    contract. A step that cannot state it is subtracted.
    ``action`` and ``content`` are content surfaces — data, screened
    for authority claims, never obeyed as instructions about authority.
    """

    capability: str
    action: str
    serves_scope: str = ""
    min_tier: int = 1
    content: str = ""
    keywords: list[str] = field(default_factory=list)


@dataclass
class RunResult:
    status: RunStatus
    reasons: list[str] = field(default_factory=list)
    receipts: list[dict] = field(default_factory=list)
    step_decisions: list[dict] = field(default_factory=list)
    executed_steps: list[int] = field(default_factory=list)
    subtracted_steps: list[int] = field(default_factory=list)
    total_cost: float = 0.0
    reuse_hits: list[str] = field(default_factory=list)
    labeled_claims: list[dict] = field(default_factory=list)
    receipts_complete: bool = False
    halted_at: "str | None" = None
    run_id: "str | None" = None
    # Strengthening pass: bound-owner flag (unbound runs must never
    # look identical to bound runs), the error that aborted the run,
    # and required capabilities that never executed.
    owner_bound: bool = True
    error: "str | None" = None
    missing_capabilities: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# The supervisor
# ---------------------------------------------------------------------------

class Supervisor:
    """Mediates every step of a run under the owner's contract,
    authority dial, route table and budget."""

    def __init__(
        self,
        authority: Authority,
        *,
        held_capabilities=frozenset(),
        route_table: "RouteTable | None" = None,
        reuse_registry=None,
    ) -> None:
        self.authority = authority
        self.held_capabilities = frozenset(held_capabilities)
        self.route_table = route_table or RouteTable()
        self.reuse_registry = reuse_registry

    # -- main entry ---------------------------------------------------------

    def run(
        self,
        task: str,
        contract: ScopeContract,
        steps: "list[ProposedStep]",
        *,
        budget=None,
        receipts_path=None,
        receipt_store=None,
        run_id=None,
    ) -> RunResult:
        # While a receipt store is attached, dial changes are recorded
        # into it (item 4); the listener is removed when the run ends,
        # unless it was already attached before this run.
        newly_attached = False
        if receipt_store is not None and hasattr(
            receipt_store, "attach_authority"
        ):
            newly_attached = receipt_store.attach_authority(self.authority)
        try:
            result = self._run(
                task,
                contract,
                steps,
                budget=budget,
                receipts_path=receipts_path,
                receipt_store=receipt_store,
                run_id=run_id,
            )
        finally:
            if newly_attached:
                receipt_store.detach_authority(self.authority)
        # Unbound authority is dev-only (F-01): leave a standalone
        # OWNER_UNBOUND warning record in the store, so an unbound run
        # can never look identical to a bound one.
        if receipt_store is not None and not self.authority.owner_bound:
            receipt_store.record_owner_warning(result.run_id)
        return result

    def _run(
        self,
        task: str,
        contract: ScopeContract,
        steps: "list[ProposedStep]",
        *,
        budget=None,
        receipts_path=None,
        receipt_store=None,
        run_id=None,
    ) -> RunResult:
        # Slice 2 (opt-in): stream every receipt into a persistent
        # store as it is emitted, under ``run_id`` (generated when
        # not given). Default: no store — behavior unchanged.
        if receipt_store is not None and run_id is None:
            run_id = "run-" + uuid.uuid4().hex[:12]
        sink = None
        if receipt_store is not None:
            sink = lambda receipt: receipt_store.append(run_id, receipt)
        log = ReceiptLog(sink=sink)
        result = RunResult(status=RunStatus.SUCCESS)
        result.run_id = run_id
        result.owner_bound = self.authority.owner_bound
        spent = Decimal("0")

        # ---- Intake (once) ---------------------------------------------
        try:
            intake = run_intake(
                task,
                contract,
                log,
                reuse_registry=self.reuse_registry,
                authority=self.authority,
                run_budget=budget,
                routes=self.route_table.routes,
            )
        except Exception as exc:
            # A crash can never look successful (item 5).
            result.status = RunStatus.ABORTED
            result.error = f"{type(exc).__name__}: {exc}"
            result.halted_at = "Intake"
            result.reasons.append(
                f"Intake raised unexpectedly; run ABORTED: {result.error}"
            )
            return self._close(log, result, spent, receipts_path)
        result.reuse_hits = intake.reuse_hits
        result.labeled_claims = intake.labeled_claims
        if intake.blocked:
            result.status = intake.status
            result.halted_at = intake.halted_at
            result.reasons.extend(intake.reasons)
            return self._close(log, result, spent, receipts_path)

        # Effective ceiling (F-03): the contract budget is
        # authoritative; a run-level budget may only tighten it.
        # Intake has already refused any loosening attempt and every
        # non-finite or negative amount, so this cannot raise.
        ceiling = contract.budget
        if budget is not None:
            run_amount = (
                budget if isinstance(budget, Decimal) else Decimal(str(budget))
            )
            ceiling = (
                run_amount if ceiling is None else min(ceiling, run_amount)
            )

        # ---- Step loop (mediated, one step at a time) ------------------
        scope_keywords = {k.lower() for k in contract.scope_keywords}
        spent = self._mediate_steps(
            contract, steps, scope_keywords, ceiling, log, result, spent
        )

        # Required capabilities (item 6 — owner decision: ENFORCE).
        # A run may end SUCCESS only if every capability the
        # contract requires was EXECUTED at least once; otherwise
        # it is INCOMPLETE, with the missing capabilities named
        # in the Closeout receipt.
        if result.status is RunStatus.SUCCESS and contract.required_capabilities:
            executed_capabilities = {
                steps[j].capability for j in result.executed_steps
            }
            missing = [
                cap
                for cap in contract.required_capabilities
                if cap not in executed_capabilities
            ]
            if missing:
                result.status = RunStatus.INCOMPLETE
                result.missing_capabilities = missing
                result.reasons.append(
                    "Required capabilities never executed: "
                    + ", ".join(missing)
                    + "; run is INCOMPLETE, not SUCCESS."
                )

        return self._close(log, result, spent, receipts_path)

    def _mediate_steps(
        self, contract, steps, scope_keywords, ceiling, log, result, spent
    ) -> Decimal:
        """The per-step mediation loop (gates in the module
        docstring). Wrapped so an unexpected exception during a
        step ABORTS the run (item 5): the step is receipted
        ABORTED, the Closeout carries the error, and SUCCESS is
        impossible for the run."""
        stage = None
        i = None
        step = None
        try:
            for i, step in enumerate(steps):
                stage = f"Step:{i}"
                decision = {
                    "index": i,
                    "capability": step.capability,
                    "action": step.action,
                    "decision": None,
                    "route": None,
                    "cost": 0.0,
                    "reason": "",
                }

                # 1) Injection screen — content can never grant authority.
                #    Every text surface of the step is screened: action,
                #    content, serves_scope and keywords. A claim carried
                #    in ANY of them denies the step outright (D-004);
                #    scanning only some surfaces leaves the others as
                #    evasion channels (tuning regression, 2026-10-23).
                attempts = (
                    scan_for_injection(step.action)
                    + scan_for_injection(step.content)
                    + scan_for_injection(step.serves_scope)
                    + scan_for_injection(" ".join(step.keywords or []))
                )
                if attempts:
                    reason = (
                        "Content attempted to grant authority mid-run; step "
                        "DENIED and attempt receipted (CONTENT CANNOT GRANT "
                        "AUTHORITY; NO SILENT ESCALATION)."
                    )
                    decision["decision"] = "DENIED"
                    decision["reason"] = reason
                    result.step_decisions.append(decision)
                    log.add(
                        stage,
                        "DENIED",
                        **decision,
                        injection_attempts=attempts,
                    )
                    result.status = RunStatus.DENIED
                    result.halted_at = stage
                    result.reasons.append(f"{stage}: {reason}")
                    break

                # 2) Negative Step Zero, per step — no trace to contract,
                #    no execution. The step is SUBTRACTED, the run goes on.
                trace_missing = not (step.serves_scope or "").strip()
                keyword_mismatch = (
                    bool(scope_keywords)
                    and bool(step.keywords)
                    and scope_keywords.isdisjoint(
                        {k.lower() for k in step.keywords}
                    )
                )
                if trace_missing or keyword_mismatch:
                    reason = (
                        "Step does not trace to the scope contract "
                        "(no serves_scope link)"
                        if trace_missing
                        else "Step keywords do not intersect the contract scope"
                    ) + "; SUBTRACTED (Negative Step Zero, per step)."
                    decision["decision"] = "SUBTRACTED"
                    decision["reason"] = reason
                    result.step_decisions.append(decision)
                    result.subtracted_steps.append(i)
                    log.add(stage, "SUBTRACTED", **decision, injection_attempts=[])
                    continue

                # 3) Authority re-check for THIS step's capability.
                held = step.capability in self.held_capabilities
                level = self.authority.level_for(step.capability)
                deny_reason = None
                if not held:
                    deny_reason = (
                        f"Capability '{step.capability}' is not held; authority "
                        "alone cannot execute it (CAPABILITY != AUTHORITY)."
                    )
                elif level is None:
                    deny_reason = (
                        f"No authority set for capability '{step.capability}'; "
                        "unset permission fails closed (DENIED)."
                    )
                elif level is PermissionLevel.NEVER:
                    deny_reason = (
                        f"Permission for capability '{step.capability}' is "
                        "NEVER (owner dial)."
                    )
                if deny_reason is not None:
                    decision["decision"] = "DENIED"
                    decision["reason"] = deny_reason
                    result.step_decisions.append(decision)
                    log.add(
                        stage,
                        "DENIED",
                        **decision,
                        held=held,
                        permission=(level.name if level else None),
                        injection_attempts=[],
                    )
                    result.status = RunStatus.DENIED
                    result.halted_at = stage
                    result.reasons.append(f"{stage}: {deny_reason}")
                    break

                # 4) Approval gate — ASK_FIRST halts; the step never runs.
                if level is PermissionLevel.ASK_FIRST:
                    reason = (
                        f"Capability '{step.capability}' is ASK_FIRST (owner "
                        "dial); step halted for approval and NOT executed."
                    )
                    decision["decision"] = "AWAITING_APPROVAL"
                    decision["reason"] = reason
                    result.step_decisions.append(decision)
                    log.add(stage, "AWAITING_APPROVAL", **decision, injection_attempts=[])
                    result.status = RunStatus.AWAITING_APPROVAL
                    result.halted_at = stage
                    result.reasons.append(f"{stage}: {reason}")
                    break

                # 5) Cheapest capable route, debited against the hard ceiling.
                route = self.route_table.cheapest_capable(
                    step.capability, step.min_tier
                )
                if route is None:
                    reason = (
                        f"No capable route for capability '{step.capability}' "
                        f"at tier >= {step.min_tier}; step DENIED (fail closed)."
                    )
                    decision["decision"] = "DENIED"
                    decision["reason"] = reason
                    result.step_decisions.append(decision)
                    log.add(stage, "DENIED", **decision, injection_attempts=[])
                    result.status = RunStatus.DENIED
                    result.halted_at = stage
                    result.reasons.append(f"{stage}: {reason}")
                    break

                if ceiling is not None and spent + route.cost > ceiling:
                    reason = (
                        f"Route '{route.name}' costs {route.cost} but only "
                        f"{ceiling - spent} of the budget ceiling {ceiling} "
                        "remains; run halted cleanly BEFORE the step "
                        "(budget is a hard ceiling)."
                    )
                    decision["decision"] = "BUDGET_HALTED"
                    decision["route"] = route.name
                    decision["reason"] = reason
                    result.step_decisions.append(decision)
                    log.add(
                        stage,
                        "BUDGET_HALTED",
                        **decision,
                        route_cost=float(route.cost),
                        budget_spent=float(spent),
                        budget_ceiling=float(ceiling),
                        injection_attempts=[],
                    )
                    result.status = RunStatus.BUDGET_HALTED
                    result.halted_at = stage
                    result.reasons.append(f"{stage}: {reason}")
                    break

                # Execute — governed record only in Slice 1 (see module doc).
                spent += route.cost
                decision["decision"] = "EXECUTED"
                decision["route"] = route.name
                decision["cost"] = float(route.cost)
                decision["reason"] = (
                    f"Authorized (dial ALONE), traced to contract, routed "
                    f"via cheapest capable route '{route.name}' "
                    f"(tier {route.tier})."
                )
                result.step_decisions.append(decision)
                result.executed_steps.append(i)
                log.add(
                    stage,
                    "EXECUTED",
                    **decision,
                    route_tier=route.tier,
                    budget_spent=float(spent),
                    budget_ceiling=(float(ceiling) if ceiling is not None else None),
                    injection_attempts=[],
                )

        except Exception as exc:
            result.status = RunStatus.ABORTED
            result.error = f"{type(exc).__name__}: {exc}"
            result.halted_at = stage
            if i is not None and not any(
                d["index"] == i for d in result.step_decisions
            ):
                result.step_decisions.append(
                    {
                        "index": i,
                        "capability": getattr(step, "capability", "?"),
                        "action": getattr(step, "action", ""),
                        "decision": "ABORTED",
                        "route": None,
                        "cost": 0.0,
                        "reason": (
                            "Unexpected error during mediation: "
                            f"{result.error}; step NOT executed "
                            "and the run ABORTED (a crash can "
                            "never look successful)."
                        ),
                    }
                )
            if stage is not None and not any(
                rec["stage"] == stage for rec in log.receipts
            ):
                decision = next(
                    d for d in result.step_decisions if d["index"] == i
                )
                log.add(
                    stage,
                    "ABORTED",
                    **decision,
                    error_type=type(exc).__name__,
                    error=str(exc),
                    injection_attempts=[],
                )
            result.reasons.append(
                f"{stage}: unexpected error during mediation; "
                f"run ABORTED: {result.error}"
            )
        return spent

    # -- closeout -----------------------------------------------------------

    def _close(self, log: ReceiptLog, result: RunResult, spent: Decimal, receipts_path) -> RunResult:
        result.total_cost = float(spent)
        closeout_details = dict(
            total_cost=result.total_cost,
            executed_steps=list(result.executed_steps),
            subtracted_steps=list(result.subtracted_steps),
            step_decisions=len(result.step_decisions),
            halted_at=result.halted_at,
        )
        if result.error is not None:
            closeout_details["error"] = result.error
        if result.missing_capabilities:
            closeout_details["missing_capabilities"] = list(
                result.missing_capabilities
            )
        log.add(
            "Closeout",
            result.status.name,
            **closeout_details,
        )
        result.receipts = log.receipts
        result.receipts_complete = receipts_chain_complete(log.receipts)
        if result.status is RunStatus.SUCCESS and not result.receipts_complete:
            # A run is only SUCCESS if its receipt chain is complete.
            result.status = RunStatus.BLOCKED
            result.reasons.append(
                "Receipt chain incomplete; SUCCESS refused (fail closed)."
            )
        if receipts_path is not None:
            log.write_jsonl(receipts_path)
        return result


def run_pipeline(
    task: str,
    contract: ScopeContract,
    authority: Authority,
    *,
    steps=(),
    held_capabilities=frozenset(),
    routes=(),
    budget=None,
    reuse_registry=None,
    receipts_path=None,
    receipt_store=None,
    run_id=None,
) -> RunResult:
    """Convenience entry point: build a Supervisor and run it."""
    supervisor = Supervisor(
        authority,
        held_capabilities=held_capabilities,
        route_table=RouteTable(list(routes)),
        reuse_registry=reuse_registry,
    )
    return supervisor.run(
        task,
        contract,
        list(steps),
        budget=budget,
        receipts_path=receipts_path,
        receipt_store=receipt_store,
        run_id=run_id,
    )
