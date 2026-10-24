"""bellaOS Pro — Sovereign Kernel core (Slice 1).

Types, the authority model, and the intake stages of the canonical
execution path. The per-step runtime mediation loop lives in
``bellaos_pro.supervisor``.

Invariants enforced here (from the owner's spec):

    MESSAGE != COMMAND != PERMISSION != EXECUTION
    CAPABILITY != AUTHORITY
    CONTENT CANNOT GRANT AUTHORITY
    NO SILENT ESCALATION
    NO UNVERIFIED MEMORY PROMOTION
    NO PRODUCTION CLAIM FROM A SPEC ALONE

Fail closed on uncertainty. Standard library only.

Design note (owner revision, 2026-10-23): Bella is a runtime supervisor,
not a one-pass preflight. Intake (this module) frames and validates the
run once; the Supervisor then re-checks authority, scope-traceability,
routing and budget for EVERY proposed step before it may execute.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from pathlib import Path

__all__ = [
    "INTAKE_STAGES",
    "Authority",
    "AuthorityError",
    "Claim",
    "EvidenceLabel",
    "IntakeOutcome",
    "PermissionLevel",
    "Principal",
    "ReceiptLog",
    "RunStatus",
    "ScopeContract",
    "run_intake",
    "scan_for_injection",
]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EvidenceLabel(Enum):
    """Ternary evidence state attached to every claim."""

    VERIFIED = "VERIFIED"
    INFERENCE = "INFERENCE"
    UNRESOLVED = "UNRESOLVED"


class PermissionLevel(Enum):
    """The owner-controlled permission dial. One level per capability."""

    ALONE = "ALONE"          # the run may use the capability without asking
    ASK_FIRST = "ASK_FIRST"  # halt and wait for the owner before use
    NEVER = "NEVER"          # the capability is forbidden, full stop


class RunStatus(Enum):
    SUCCESS = "SUCCESS"
    BLOCKED = "BLOCKED"                        # intake gate refused the run
    DENIED = "DENIED"                          # capability/authority failure
    AWAITING_APPROVAL = "AWAITING_APPROVAL"    # ASK_FIRST halt
    BUDGET_HALTED = "BUDGET_HALTED"            # hard budget ceiling reached


# ---------------------------------------------------------------------------
# Principals and authority
# ---------------------------------------------------------------------------

class AuthorityError(Exception):
    """Raised when a non-owner principal attempts to set authority."""


@dataclass(frozen=True)
class Principal:
    """An actor identity. Only the owner principal carries authority."""

    name: str
    role: str  # "owner" | "requester" | "agent" | "content"

    @classmethod
    def owner(cls, name: str = "owner") -> "Principal":
        return cls(name=name, role="owner")

    @property
    def is_owner(self) -> bool:
        return self.role == "owner"


class Authority:
    """The permission dial: capability -> PermissionLevel.

    Authority can be set ONLY through this API and ONLY by the owner
    principal. Task text, step text, tool output and any other content
    are data: they are never parsed into authority. Content that claims
    authorization is receipted as an injection attempt (see
    ``scan_for_injection``) and changes nothing here.

    CAPABILITY != AUTHORITY: this table says what is *allowed*; the set
    of held capabilities (passed to the supervisor separately) says
    what is *possible*. Both must line up before anything executes.
    """

    def __init__(self) -> None:
        self._levels: dict[str, PermissionLevel] = {}

    def set_permission(
        self,
        capability: str,
        level: "PermissionLevel | str",
        *,
        principal: Principal,
    ) -> None:
        if principal is None or not getattr(principal, "is_owner", False):
            raise AuthorityError(
                "only the owner principal may set authority; "
                "content cannot grant authority"
            )
        if isinstance(level, str):
            level = PermissionLevel[level]
        self._levels[str(capability)] = level

    def level_for(self, capability: str) -> "PermissionLevel | None":
        """Return the dial level for a capability, or None if unset.

        Unset means DENY (fail closed); callers must not treat None as
        permissive.
        """
        return self._levels.get(str(capability))

    def snapshot(self) -> dict[str, str]:
        return {cap: lvl.name for cap, lvl in sorted(self._levels.items())}


# ---------------------------------------------------------------------------
# Injection screening (content can never grant authority)
# ---------------------------------------------------------------------------

_INJECTION_PATTERNS = [
    r"you are (now )?(authorized|authorised)",
    r"i (hereby )?grant (you )?(permission|authorization|authorisation)",
    r"permission (has been |is )?granted",
    r"you have (my |full )*permission",
    r"i authorize you",
    r"i authorise you",
    r"as (the )?owner[,.]? i (approve|authorize|authorise|grant)",
    r"the owner (has )?(approved|authorized|authorised|granted)",
    r"owner (has )?(approved|authorized|authorised|granted)",
    r"ignore (the )?(authority|permission|approval) (gate|check|requirement)",
    r"skip (the )?(authority|permission|approval)( gate| check)?",
    r"pre-?approved by (the )?owner",
]

_INJECTION_RES = [re.compile(p, re.IGNORECASE) for p in _INJECTION_PATTERNS]


def scan_for_injection(text: str) -> list[dict]:
    """Find authorization claims inside content.

    Returns a list of {"pattern", "excerpt"} findings. Findings are for
    receipts only: a match NEVER changes authority. At intake the run
    proceeds on the real authority table (and fails closed if the dial
    is unset); inside the supervisor loop, a step carrying such a claim
    is denied outright as an escalation attempt.
    """
    if not text:
        return []
    findings = []
    for rx in _INJECTION_RES:
        for m in rx.finditer(text):
            findings.append({"pattern": rx.pattern, "excerpt": m.group(0)})
    return findings


# ---------------------------------------------------------------------------
# Claims and the scope contract
# ---------------------------------------------------------------------------

@dataclass
class Claim:
    """A statement plus its ternary evidence label.

    An unlabeled claim resolves to UNRESOLVED — never silently promoted
    (NO UNVERIFIED MEMORY PROMOTION).
    """

    statement: str
    label: "EvidenceLabel | str | None" = None

    def __post_init__(self) -> None:
        if isinstance(self.label, str):
            self.label = EvidenceLabel[self.label]

    def resolved_label(self) -> EvidenceLabel:
        return self.label if self.label is not None else EvidenceLabel.UNRESOLVED

    def as_dict(self) -> dict:
        return {"statement": self.statement, "label": self.resolved_label().name}


@dataclass
class ScopeContract:
    """The typed contract a run executes under.

    The contract + the authority table together express the user's best
    interest; in the supervisor's objective hierarchy they are hard
    limits that are never traded away for logic or cost.
    """

    task: str
    problem: str           # the problem this run exists to solve
    scope: str             # what is in bounds
    output_contract: str   # what the run must deliver
    requester: "Principal | str"
    required_capabilities: list[str] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    budget: "Decimal | float | int | str | None" = None  # hard ceiling
    scope_keywords: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.budget is not None and not isinstance(self.budget, Decimal):
            self.budget = Decimal(str(self.budget))
        self.claims = [
            c if isinstance(c, Claim) else Claim(str(c)) for c in self.claims
        ]

    def requester_name(self) -> str:
        if isinstance(self.requester, Principal):
            return self.requester.name
        return str(self.requester)


# ---------------------------------------------------------------------------
# Receipts
# ---------------------------------------------------------------------------

class ReceiptLog:
    """Append-only receipt chain. Every stage and every step writes
    exactly one receipt; a run's record is complete only if the chain is
    whole and in order (NO SILENT ESCALATION — every refusal, halt and
    injection attempt lands here)."""

    def __init__(self) -> None:
        self.receipts: list[dict] = []

    def add(self, stage: str, status: str, **details) -> dict:
        receipt = {
            "seq": len(self.receipts),
            "stage": stage,
            "status": status,
            "ts": time.time(),
            "details": details,
        }
        self.receipts.append(receipt)
        return receipt

    def write_jsonl(self, path: "str | Path") -> None:
        text = "\n".join(json.dumps(r) for r in self.receipts)
        Path(path).write_text(text + ("\n" if text else ""), encoding="utf-8")


def receipts_chain_complete(receipts: list[dict]) -> bool:
    """Verify the chain: seq 0..n-1, intake receipts an ordered prefix
    of INTAKE_STAGES, step receipts (``Step:<i>``) contiguous from 0 in
    order after intake, and a final Closeout receipt."""
    if not receipts:
        return False
    if [r["seq"] for r in receipts] != list(range(len(receipts))):
        return False
    stages = [r["stage"] for r in receipts]
    if stages[-1] != "Closeout":
        return False
    body = stages[:-1]
    intake_part = [s for s in body if not s.startswith("Step:")]
    step_part = [s for s in body if s.startswith("Step:")]
    if body != intake_part + step_part:
        return False
    if intake_part != INTAKE_STAGES[: len(intake_part)]:
        return False
    step_idx = [int(s.split(":", 1)[1]) for s in step_part]
    if step_idx != list(range(len(step_idx))):
        return False
    return True


# ---------------------------------------------------------------------------
# Intake — runs once, before any step is proposed
# ---------------------------------------------------------------------------

INTAKE_STAGES = [
    "StepZero",
    "ReuseCheck",
    "NegativeStepZero",
    "ScopeContract",
    "EvidenceLabeling",
]

_NO_PROBLEM_VALUES = {"", "none", "n/a", "na", "no problem", "nothing", "-"}


@dataclass
class IntakeOutcome:
    blocked: bool
    status: "RunStatus | None" = None
    halted_at: "str | None" = None
    reasons: list[str] = field(default_factory=list)
    reuse_hits: list[str] = field(default_factory=list)
    labeled_claims: list[dict] = field(default_factory=list)


def _load_registry(reuse_registry) -> dict:
    if reuse_registry is None:
        return {}
    if isinstance(reuse_registry, dict):
        return dict(reuse_registry)
    data = json.loads(Path(reuse_registry).read_text(encoding="utf-8"))
    return dict(data)


def run_intake(
    task: str,
    contract: ScopeContract,
    log: ReceiptLog,
    *,
    reuse_registry=None,
) -> IntakeOutcome:
    """Run the intake stages once. On a block, the returned outcome
    carries the halting stage and reason; the caller must not proceed
    to the step loop."""

    # -- Step Zero: frame the task; screen content for authority claims.
    content_surfaces = [
        task or "",
        contract.problem or "",
        contract.scope or "",
        contract.output_contract or "",
    ] + [c.statement for c in contract.claims]
    injection_attempts: list[dict] = []
    for surface in content_surfaces:
        injection_attempts.extend(scan_for_injection(surface))
    log.add(
        "StepZero",
        "PASS",
        task=task,
        requester=contract.requester_name(),
        required_capabilities=list(contract.required_capabilities),
        injection_attempts=injection_attempts,
        note=(
            "Authorization claims found in content are receipted here "
            "and ignored: content cannot grant authority."
            if injection_attempts
            else "No authorization claims detected in content."
        ),
    )

    # -- Reuse check: consult the registry before building anything new.
    registry = _load_registry(reuse_registry)
    haystacks = [(task or "").lower(), (contract.scope or "").lower()]
    hits = [
        key
        for key in registry
        if any(key.lower() in h for h in haystacks)
    ]
    log.add(
        "ReuseCheck",
        "HIT" if hits else "MISS",
        hits=hits,
        registry_size=len(registry),
        note=(
            "Reuse candidates are INFERENCE until verified against the "
            "contract; a hit never widens scope or authority."
        ),
    )

    # -- Negative Step Zero (run level): no stated problem, no run.
    problem = (contract.problem or "").strip()
    if problem.lower() in _NO_PROBLEM_VALUES:
        reason = (
            "NegativeStepZero: the contract states no problem to solve; "
            "run blocked (fail closed)."
        )
        log.add("NegativeStepZero", "BLOCKED", reason=reason)
        return IntakeOutcome(
            blocked=True,
            status=RunStatus.BLOCKED,
            halted_at="NegativeStepZero",
            reasons=[reason],
            reuse_hits=hits,
        )
    log.add("NegativeStepZero", "PASS", problem=problem)

    # -- Scope contract validation.
    missing = []
    if not (contract.task or "").strip():
        missing.append("task")
    if contract.task and task and contract.task.strip() != task.strip():
        missing.append("task_mismatch(contract.task != run task)")
    if not (contract.scope or "").strip():
        missing.append("scope")
    if not (contract.output_contract or "").strip():
        missing.append("output_contract")
    if not contract.requester_name().strip():
        missing.append("requester")
    if missing:
        reason = (
            "ScopeContract: contract is incomplete or inconsistent; "
            f"missing/invalid: {', '.join(missing)}. Run blocked (fail closed)."
        )
        log.add("ScopeContract", "BLOCKED", reason=reason, missing=missing)
        return IntakeOutcome(
            blocked=True,
            status=RunStatus.BLOCKED,
            halted_at="ScopeContract",
            reasons=[reason],
            reuse_hits=hits,
        )
    log.add(
        "ScopeContract",
        "PASS",
        scope=contract.scope,
        output_contract=contract.output_contract,
        budget=(str(contract.budget) if contract.budget is not None else None),
    )

    # -- Evidence labeling: every claim carries its ternary label.
    labeled = [c.as_dict() for c in contract.claims]
    log.add(
        "EvidenceLabeling",
        "PASS",
        claims=labeled,
        note="Unlabeled claims default to UNRESOLVED; nothing is promoted silently.",
    )

    return IntakeOutcome(
        blocked=False,
        reuse_hits=hits,
        labeled_claims=labeled,
    )
