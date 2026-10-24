# bellaOS Pro — Module Registry

The ecosystem bellaOS Pro assembles, by layer. Evidence states use the
owner's ladder honestly: **nothing in this ecosystem has been assembled
into bellaOS Pro yet**, so no module is claimed above UNPROVEN /
NOT TESTED. A spec, a repo, or a passing local test in isolation is
not production evidence (NO PRODUCTION CLAIM FROM A SPEC ALONE).

| Module | Layer | Repo | Role in the assembly | Evidence state |
|---|---|---|---|---|
| bellaOS | L0 — Constitution | `michaelchaves-dev/bellaOS` | Constitutional root: principles, governing methods, the invariants every lower layer cites. Also home of the BRUTO security layer. | UNPROVEN |
| bellaos-brain | L0/L1 support | `michaelchaves-dev/bellaos-brain` | Doctrine / living method knowledge (RAG) feeding the constitution and Sentinel. Supports L0/L1; holds no runtime authority. | NOT TESTED |
| Sovereign Kernel + Runtime Supervisor | L1 — Truth & Evidence | `michaelchaves-dev/bellaOS_Pro` (this build) | Canonical execution path, ternary evidence labels (VERIFIED / INFERENCE / UNRESOLVED), permission dial enforcement, receipts. Slice 1 built locally — see BUILD_STATE.md. | UNPROVEN (assembly); Slice 1 local unit evidence in BUILD_STATE.md |
| CNS-Memory-Core | L2 — Memory | `michaelchaves-dev/CNS-Memory-Core` | Durable state, provenance, reuse. Memory promotion into CNS is gated by the kernel — never automatic. Note: the 2026-10-23 repo sweep flagged a hardcoded fallback API key on its main branch; the removal fix is pending the owner's approval, so treat the module as untrusted until rotated. | UNPROVEN |
| ZeroFold | L2 — Memory (context conservation) | `michaelchaves-dev/ZeroFold` | Context reduction / representation with provenance surviving compression. Paired with CNS under L2. | NOT TESTED |
| subtractoken-router (SubtracToken) | L3 — Routing & Economics | `michaelchaves-dev/subtractoken-router` | Model/provider egress, cost/capability routing, budgets, caching, measurable inference economics. The supervisor's route table is the L1-side contract this module will implement against. | UNPROVEN |
| bellaOS-Agent-Control-Plane | L4 — Orchestration | `michaelchaves-dev/bellaOS-Agent-Control-Plane` | Orchestration, permissions, handoffs, stop conditions, execution control for governed agents ("Baby Bella" architecture). | UNPROVEN |
| Sentinel / Secure-Gate / BRUTO | L5 — Security | Sentinel components; BRUTO lives in `michaelchaves-dev/bellaOS` | Integrity, security, ingress/egress screening and enforcement. Fail-closed. | NOT TESTED |
| RelAI | L6 — Challenge | Ecosystem component (no runtime surface yet) | Independent reasoning, competition and challenge of outputs before delivery, when stakes warrant. | NOT TESTED |
| Owner Console | L7 — Sovereignty | `michaelchaves-dev/bellaOS_Pro` (future slice) | The user's surface: permission dial UI, plain-language receipts viewer, memory inspection/export, kill switch. Not built. | NOT TESTED |
| bellaOS-Commons | Coordination — NOT a runtime layer | `michaelchaves-dev/bellaOS-Commons` | Permissioned coordination, shared evidence, canonical maps, nominations between agents. Explicitly not runtime authority: nothing in Commons can authorize execution. | UNPROVEN |

## Reading rules

- A module's evidence state changes only with assembled, tested,
  receipted evidence — reviewed by Roman, promoted by the owner.
- Coordination surfaces (Commons) and knowledge surfaces (brain) can
  inform a run; they can never authorize one.
