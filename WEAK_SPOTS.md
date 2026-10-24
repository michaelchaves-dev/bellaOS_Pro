# bellaOS Pro — Red Team Weak-Spots Report (Slices 0–2)

Reviewer role: adversarial review, read-only. Scope: `bellaos_pro/kernel.py`,
`bellaos_pro/supervisor.py`, `bellaos_pro/receipts.py`, tests
(`test_kernel.py`, `test_supervisor.py`, `test_receipts.py`), against
BUILD_STATE.md, DECISIONS.md, and the owner's invariants.

Method note: findings are from code tracing, not from running the suite.
Where a sketch depends on co-residency (attacker code in the same process)
or on a later slice, that dependence is stated — Slice 1's embedding app
is currently the root of trust, and several findings are " prototype-OK,
fatal at L4 / tool-execution time" by design of the threat model this
system is explicitly being built for: mediating *untrusted* agents and
content.

---

## Findings, ranked by severity × likelihood

### CRITICAL

#### F-01 — The owner principal is self-asserted; anyone can mint an owner
- **Flaw:** `Principal.is_owner` is `role == "owner"` on a plain dataclass,
  and `Authority.set_permission` checks only `getattr(principal, "is_owner", False)`.
- **Sketch:** `Authority().set_permission("wire_transfer", ALONE, principal=Principal("mallory", "owner"))`
  succeeds. Even simpler, any duck-typed object works:
  `set_permission(..., principal=SimpleNamespace(is_owner=True))`.
  The existing test only proves the strings `"requester"` and `"content"`
  are rejected — it never tests that "owner" can't be fabricated, because
  it can.
- **Downstream:** D-004 ("authority is set only by the owner, only via API")
  is enforced as a *convention*, not a control. At L4, every sub-agent that
  can import this module is one constructor call from being the owner, and
  every other gate (dial, budget, approval) sits behind this one.
- **Strengthening:** Bind ownership to a secret the agent layer cannot
  reach: `Authority` is constructed with an owner token (or HMAC key);
  `set_permission` requires presenting it. Until then, document in
  DECISIONS.md that Principal is an *assertion*, not authentication, so
  no later slice mistakes it for a security boundary.

#### F-02 — The receipt chain is keyless: total rewrite and suffix-continuation attacks are undetectable
- **Flaw:** The hash chain uses unkeyed sha256 over public data with a
  public algorithm; the hash covers only the four body fields, and
  `_scan_tail` resumes from whatever tail it finds without verification.
- **Sketch (total rewrite):** Any process that can write the store file
  can regenerate the entire file from genesis with invented receipts —
  every hash recomputes correctly, `verify_chain` returns OK.
- **Sketch (suffix + forged continuation):** Truncate the file at record
  *k* (deleting, say, every DENIED receipt after it), append a forged
  record *k+1* with `prev_hash` = hash of record *k* and a correctly
  computed hash. The chain verifies. Worse, the next *legitimate* append
  calls `_scan_tail`, adopts the forged tail as `_last_hash`, and chains
  honest receipts on top of the forgery — laundering it. The known
  suffix-deletion gap is therefore worse than "deletion is invisible":
  deletion plus continuation is *permanently* invisible.
- **Sketch (extra-field smuggling):** `record_hash` covers only
  `run_id/seq/prev_hash/receipt`. An editor can add top-level fields
  (`"audited": true`, `"note": "owner approved"`) to any record without
  breaking verification; any future console that renders record fields
  will display unauthenticated data as if sealed.
- **Downstream:** The store is the system's evidence of record — the
  thing Slice 3 memory promotion, the L7 console, and any dispute with
  a user will rely on. Keyless, it is tamper-evident only against an
  attacker who cannot do arithmetic. The intended threat model (agents
  running with filesystem access) includes exactly that attacker.
- **Anchor options, evaluated:**
  - **HMAC-signed head (recommended first step).** Closeout (and
    periodically) the store head `(last_hash, record_count)` is signed
    with HMAC-SHA256 under an owner-held key (stdlib `hmac` — no new
    dependency, fits D-003). Detects total rewrite and suffix attacks
    *provided the signature record lives outside the JSONL* (separate
    small file, owner-writable only). Cost: key management — where the
    key lives becomes the new root-of-trust question; rotation story
    needed. Size: **M**.
  - **External checkpoint.** Publish the head hash somewhere the writer
    cannot rewrite (the bellaOS-Commons board, a git commit, an email
    to the owner). Strongest independence; cost is infrastructure and a
    vulnerability window between checkpoints. Size: **M** + ongoing ops.
  - **Monotonic run registry.** A separate registry file recording, per
    run, `(first_seq, last_seq, head_hash, receipt_count)` at closeout.
    Detects suffix loss per run *only if* the registry has stricter
    write access than the store; same-directory/same-user, it is a
    tripwire against accidents, not adversaries. Cost: **S**, value:
    real but limited — do it, don't oversell it.
  - Also: hash *all* record fields (hash the canonical form of the
    entire record minus `hash` itself) to close extra-field smuggling. **S**.

### HIGH

#### F-03 — The budget ceiling is caller-optional and caller-overridable
- **Flaw:** In `Supervisor.run`, `ceiling = budget if budget is not None else contract.budget` — the run-time parameter silently overrides the contract; if neither is set, `ceiling is None` and there is *no* budget enforcement at all; nothing validates the ceiling's value.
- **Sketch:** Contract says budget 1.00. Any caller runs
  `run_pipeline(..., budget="1000")` — the owner's hard limit is gone,
  and no receipt records that it was raised (the ScopeContract receipt
  logs the *contract's* budget). Or `ScopeContract(budget="Infinity")`:
  `Decimal("Infinity")` constructs fine and `spent + cost > Infinity`
  is never true — an infinite "hard ceiling." Or `budget="NaN"`: every
  comparison raises `decimal.InvalidOperation` mid-run (see F-07).
- **Downstream:** D-006 ("budget is a hard ceiling") is the flagship
  economic control and the hierarchy's tier-1 "user's best interest."
  At the tool-execution slice, the caller assembling runs will be agent
  infrastructure — the component most likely to benefit from a raised
  ceiling gets to raise it.
- **Strengthening:** The contract budget is the ceiling; a run parameter
  may only *lower* it. A no-ceiling run requires an explicit owner-set
  flag on the contract and is receipted as a waiver. Validate at
  construction: budget must be finite and ≥ 0, else the contract is
  rejected. **S**.

#### F-04 — Route economics are unvalidated and mutable: negative costs print budget
- **Flaw:** `Route` coerces cost to Decimal but never validates it;
  `Route` and `RouteTable.routes` are mutable and shared by reference.
- **Sketch:** `Route("free-money", "summarize", 1, "-5.00")` —
  `cheapest_capable` picks it first (min by cost), `spent` *decreases*
  per step, the ceiling can never trip, and Closeout reports negative
  spend. Tier is likewise unvalidated (negative tiers + a step-supplied
  negative `min_tier` admit junk routes). Separately, any co-resident
  holder of the `RouteTable` (or of a shared `Route` object — `run_pipeline`
  copies the list, not the routes) can mutate `route.cost` or append a
  negative route *between steps* of a live run.
- **Downstream:** Slice 3 wires this table to SubtracToken, where routes
  will be built from provider data — untrusted input. A malformed or
  malicious route entry silently inverts the budget control.
- **Strengthening:** Validate in `Route.__post_init__`: cost finite and
  ≥ 0 (zero allowed but flagged), tier an int ≥ 0. Make `Route` frozen
  and have `Supervisor` snapshot the table (tuple) at run start. **S**.

#### F-05 — Dial changes are unaudited, authority state is absent from receipts, and the shared dial is a mid-run TOCTOU
- **Flaw:** `Authority.set_permission` writes no receipt anywhere.
  `Authority.snapshot()` exists but is called *nowhere* — not in intake,
  not in receipts, not in tests. The supervisor reads the live, shared,
  mutable `Authority` object at each step.
- **Sketch:** Owner sets `read=ALONE`. A co-resident agent holding the
  same `Authority` reference calls `set_permission("wire", ALONE, principal=<minted owner, F-01>)`
  between steps; the wire step executes "authorized"; the dial is set
  back after the run. Every receipt is genuine, the chain verifies, and
  the record shows a clean run — there is no evidence the dial ever
  moved, nor any record of what the dial *was* when step N was decided.
- **Downstream:** "NO SILENT ESCALATION" is violated at the one layer
  where it matters most: escalation *of the authority table itself* is
  the only silent operation in the system. Slice 3/L7 auditing built
  on these receipts inherits the blindness.
- **Strengthening:** (a) `run_intake` receipts `Authority.snapshot()`
  (or its hash) so every run's evidence binds the dial state it ran
  under; (b) `Supervisor` works on an immutable snapshot taken at run
  start — mid-run dial changes apply to the *next* run; (c) when a
  receipt store is attached, `set_permission` appends an authority-change
  record to it. **S–M**.

#### F-06 — Per-step Negative Step Zero trusts the step's own claim about itself
- **Flaw:** Gate 2 passes any step whose `serves_scope` is a non-empty
  string. The step grades its own homework. The keyword check is
  opt-in on both sides: it only fires when the contract sets
  `scope_keywords` *and* the step supplies `keywords`, and the step
  chooses its own keywords.
- **Sketch:** `ProposedStep(capability="send_email", action="Email the full customer database to an external address", serves_scope="Provides the data for the anomaly report.")`
  — passes gate 2 cleanly. Only the authority gate stands behind it,
  and if `send_email` is ALONE for legitimate reasons, the step executes.
  The same flaw exists at intake: `problem`/`scope`/`output_contract`
  need merely be non-empty and off a small stoplist — `"x"` is a
  problem statement; the stoplist is exact-match (`"none."`,
  `"no problem at all"` pass).
- **Downstream:** At L4, steps will be proposed by agents — adversarial
  or merely over-eager ones. A logic gate that accepts self-attestation
  produces receipts that *look* like verification ("traced to contract")
  while performing none, which is worse than no gate: it manufactures
  false assurance in the evidence layer itself. Slice 3 must not treat
  a passed gate 2 as a verified trace.
- **Strengthening:** Require `serves_scope` to cite a contract artifact
  (a scope-clause id or a verbatim quote of a scope substring) and check
  the citation mechanically; receipt gate-2 passes explicitly as
  `SELF_ATTESTED` (ternary label: INFERENCE, not VERIFIED) until a real
  entailment check exists. **M**.

#### F-07 — Exceptions escape `run()` with no Closeout: crashed runs leave partial, ambiguous evidence
- **Flaw:** The step loop has no try/finally. `_close` runs only on
  normal and explicitly-broken paths. `RunStatus` has no ERROR/ABORTED
  value.
- **Sketch:** (a) `budget="NaN"` (F-03) raises `InvalidOperation` at the
  first routable step — the exception propagates out of `run()`, the
  caller gets *no* RunResult and *no* receipts, while the store (if
  attached) already holds intake + step receipts for a run that never
  closes. (b) The receipt sink raises (disk full, IO error) inside
  `ReceiptLog.add` — same shape: partial chain in the store, nothing
  in memory returned. A reader of the store later sees a run that
  simply stops; the renderer reports its status as "unknown."
- **Downstream:** The first real tool slice *will* throw (timeouts,
  API errors) — today, every throw is an evidence hole and a run whose
  spend state is unrecoverable. Crash-safety was deferred in Slice 2;
  the kernel loop itself is where the hole opens.
- **Strengthening:** Wrap the loop: on any exception, write a Closeout
  with a new `ABORTED` status and the exception summary, mark the
  result, then re-raise (or return the aborted result — decide once,
  in DECISIONS.md). Add `RunStatus.ABORTED`. **S**.

#### F-08 — ReceiptStore write/read fragility: concurrent writers fork the chain; one bad line bricks the store
- **Flaw:** No locking, no fsync, whole-file reads, unguarded
  `json.loads` per line. `_scan_tail` reads the *entire* file to find
  the last line and trusts it unverified.
- **Sketch (fork):** Two processes construct `ReceiptStore` on the same
  path (the normal case at L4 — multiple agents, one evidence store).
  Both scan the same tail, both take the same `_next_seq`/`_last_hash`,
  both append: duplicate seqs, two children of one parent — the chain
  is corrupt *by construction*, and `verify_chain` fails on honest
  data, training operators to ignore verification failures.
- **Sketch (brick):** A crash mid-append leaves a torn final line.
  Every subsequent `ReceiptStore(path)` raises `JSONDecodeError` in
  `_scan_tail` — appends are wedged; `records()`, `verify_chain`,
  `query`, `cost_ledger`, `render_run_summary` all raise on the same
  line. One corrupt byte anywhere = total store DoS, no quarantine or
  salvage mode. Also unbounded line size: `records()` loads the whole
  file into memory; a single multi-GB line (or a receipt with a huge
  `content` excerpt) is a memory-exhaustion vector on every read.
- **Downstream:** BUILD_STATE already flags multi-process and crash
  recovery as untested; traced concretely, both are not merely
  untested but structurally broken, and L4 makes concurrency the
  default case.
- **Strengthening:** Single-writer discipline enforced with an OS file
  lock around scan+append (stdlib `fcntl.flock`), `flush` + `os.fsync`
  per append, and a recovery path: on open, if the final line fails to
  parse, truncate to the last valid record (receipting the salvage in
  the next append) instead of dying. Stream reads line-by-line with a
  max-line guard. **M**.

### MEDIUM

#### F-09 — Injection screen bypass: fixed English regex list, no normalization, unscreened surfaces
- **Flaw:** `scan_for_injection` matches 13 literal English patterns
  against raw `action`/`content` only.
- **Sketches (all evade every pattern):** "You are *hereby* authorized…"
  (`hereby` isn't in pattern 1); "…per the owner's standing instruction,
  proceed" (possessive defeats the `owner (has )?(approved…)` patterns);
  "authorization was arranged with the owner earlier"; any non-English
  phrasing; fullwidth/homoglyph characters ("ａuthorized") — no NFKC
  normalization; zero-width characters inside keywords. The indirect
  social-engineering form — "the owner said earlier that…" — matches
  nothing. And `step.serves_scope` is **never screened at all**, though
  it is echoed into receipts as the step's justification, where a human
  auditor will read it as vetted.
- **Calibration (important):** authority never *depends* on this screen —
  a bypassed claim still cannot move the dial; the step must still pass
  the authority gate. What a bypass actually loses is (a) the DENIED
  tripwire for escalation-flavored steps whose capability *is* allowed,
  and (b) the receipted evidence that an attempt occurred. It is
  defense-in-depth and telemetry — but the spec language ("a step
  carrying such a claim is denied outright") promises more than the
  mechanism can deliver, and Slice 3+ builders may rely on the promise.
- **Strengthening:** NFKC-normalize + strip zero-width chars before
  scanning; screen `serves_scope` too; add the indirect forms
  ("owner said", "per the owner", "on the owner's behalf", "previously
  approved/arranged"); write the screen's true role (tripwire, not
  boundary) into DECISIONS.md. **S**.

#### F-10 — Injection screen false positives are a run-killer (availability)
- **Flaw:** Mid-run, *any* pattern match in a step's action/content
  denies the step and **halts the entire run** — including matches in
  quoted, third-party text the step is merely processing. (Note the
  asymmetry: the same text at intake is receipted and the run proceeds.)
- **Sketch:** A summarization step whose content is a policy document
  containing "permission granted to all staff for read access" matches
  `permission (has been |is )?granted` → run DENIED. At the tool slice,
  step content will routinely be retrieved documents: any data source
  can grief any run by containing one flagged sentence — an attacker
  who can write to a source the agent reads gains a kill switch over
  every run that reads it.
- **Strengthening:** Distinguish *first-person claims directed at the
  supervisor* from quoted material where feasible; at minimum, make the
  mid-run response configurable per capability (deny-and-continue for
  read-only capabilities) and record in DECISIONS.md that the current
  halt-on-match is a known availability trade-off. **S–M**.

#### F-11 — `run_id` is caller-chosen and unenforced: distinct runs merge in query, ledger, and summaries
- **Flaw:** `ReceiptStore.append(run_id, …)` accepts any string;
  nothing enforces uniqueness.
- **Sketch:** Two different runs both stored under `"run-a"` (a retried
  job, a buggy caller, or an agent choosing ids). `query(run_id="run-a")`
  returns both runs interleaved, `cost_ledger()["per_run"]` merges
  their spend, and `render_run_summary("run-a")` narrates a chimera —
  with a fully valid hash chain underneath, so the merged evidence
  *verifies*.
- **Strengthening:** The store mints run ids (or rejects a run_id that
  already has a Closeout); at minimum, `append_run`/the sink path
  refuses a run_id already present. **S**.

#### F-12 — ASK_FIRST has no resume semantics — the gap the tool slice will fill unsafely
- **Flaw:** An AWAITING_APPROVAL run simply ends. There is no resume
  API, no approval token, no record format for "owner approved step N
  of run R."
- **Consequence (look-ahead):** The first slice that needs resume will
  invent it under time pressure. The obvious naive designs are all
  wrong: re-running the whole pipeline double-executes (and with real
  tools, double-charges / double-sends) steps 0..N−1; trusting the
  proposer to "continue from step N" lets a non-owner resume; an
  approval recorded nowhere becomes a content claim (F-09's problem,
  promoted to a mechanism).
- **Strengthening (define now, build later):** Resume = a *new* run
  whose intake references the halted run_id + step index, carrying an
  owner approval record in the receipt store; already-executed steps
  are never re-executed, their receipts are linked, not copied. Write
  this as a DECISIONS.md entry before Slice 3 starts. **S** (decision),
  M (implementation, later slice).

#### F-13 — Steps and receipts carry no proposer identity
- **Flaw:** `ProposedStep` has no proposer/principal field; step
  receipts record capability, action, route — never *who proposed this
  step*.
- **Consequence:** At L4 the first audit question after any bad step is
  "which agent proposed it?" — unanswerable from the evidence. The
  Commons model (multiple named agents) makes provenance a requirement,
  not a nicety.
- **Strengthening:** Add `proposer: str` to `ProposedStep`, receipt it
  on every step outcome. Cheap now, a migration later. **S**.

#### F-14 — Caller-asserted VERIFIED labels are accepted at face value; label provenance is unrecorded
- **Flaw:** Any contract author can construct `Claim("…", EvidenceLabel.VERIFIED)`;
  intake receipts it as VERIFIED. Nothing records *who* labeled it or on
  what evidence. The ternary system's integrity rests entirely on
  caller honesty.
- **Consequence:** Slice 3's gated memory promotion will read these
  labels. If promotion trusts a pre-set VERIFIED from any non-owner
  source, NO UNVERIFIED MEMORY PROMOTION is defeated through the front
  door — the label *is* the promotion ticket, and it's printable by
  anyone.
- **Strengthening:** Claims carry `labeled_by` (principal) and an
  evidence reference; promotion gates treat VERIFIED as authoritative
  only when `labeled_by` is the owner or a verification stage — all
  other VERIFIEDs are demoted to INFERENCE at intake, with the demotion
  receipted. **S–M**.

#### F-15 — Slice 3 readiness: global chain vs. per-run extraction, and verbatim sensitive content in receipts
- **Flaw (a):** The chain is global across runs; a single run's records
  are a subsequence whose first record points outside the run. Extracting
  one run (for memory promotion or export) produces a chain that does
  not verify standalone — Slice 3 will be tempted to bypass verification
  for extracted runs, quietly retiring the tamper-evidence property
  exactly where it matters.
- **Flaw (b):** Receipts persist task text, scope, output contract,
  step actions, and injection excerpts *verbatim, forever*, with no
  redaction or minimization layer; the renderer prints task + requester.
  Promoting receipts into CNS memory (Slice 3) copies all of it —
  including any secrets a user pastes into a task — into long-term
  memory.
- **Strengthening:** Decide the extraction story now (per-run subchain
  anchors: each run's first record also hashes the previous run's
  closeout, so a run verifies as a unit), and add a redaction pass at
  the store boundary with a receipted "redacted" marker before Slice 3
  lands. **M**.

#### F-16 — Two JSONL formats, one of them unprotected: the `receipts_path` export has no tamper evidence
- **Flaw:** `ReceiptLog.write_jsonl` writes bare kernel receipts (no
  hashes, no chain). `ReceiptStore` writes chained records. Same
  extension, same look, wildly different guarantees — and the Slice 1
  test suite's headline evidence (TestCleanFullPass) exercises the
  *unprotected* one.
- **Sketch:** An operator archives the `receipts_path` export as "the
  audit record." Anyone can edit it freely; nothing detects it. The
  format confusion, not malice, is the likely path.
- **Strengthening:** Make `write_jsonl` delegate to the chained format
  (or rename the bare export `*.receipts.jsonl` vs store
  `*.chain.jsonl` and document the difference in README_BUILD.md). **S**.

#### F-17 — Unbounded runs: no step cap, and zero-cost routes make the budget a non-limit
- **Flaw:** Nothing bounds `len(steps)`, and with a legitimate
  zero-cost route the ceiling never trips. Receipts accumulate in
  memory and (with a store) on disk, one append per step.
- **Sketch:** A proposer submits 10^7 zero-cost steps (or a generator —
  `run_pipeline` does `list(steps)`, materializing it). The run
  "succeeds" after exhausting RAM/disk with receipts. In Slice 1 this
  is a local DoS; with real tools it's a cost/rate-limit incident that
  the budget gate structurally cannot see.
- **Strengthening:** Contract-level `max_steps` (owner-set, receipted),
  enforced in the loop; treat an all-zero-cost route set as a contract
  warning at intake. **S**.

#### F-18 — The in-memory completeness check is shape-only: "complete" Slice 1 evidence is fabricable
- **Flaw:** `receipts_chain_complete` validates structure (seq order,
  stage order, final Closeout) over plain dicts — no hashes, no
  signatures. Any caller can hand-build a list that passes and present
  `receipts_complete=True`-grade evidence.
- **Calibration:** Inside `run()` the check is a self-consistency
  guard against the supervisor's own bugs, and as that, it works
  (see positives). The risk is purely presentational: BUILD_STATE /
  external claims must not describe Slice 1's in-memory chain as
  tamper-evident — only the Slice 2 store chain is, and only in the
  limited sense of F-02.
- **Strengthening:** Rename/document the check as structural
  completeness in code comments and BUILD_STATE; no code change needed
  beyond wording discipline. **S**.

### LOW

#### F-19 — Receipt timestamps are wall-clock, unauthenticated, and unverified
- `ts: time.time()` is emitter-asserted; `verify_chain` ignores it;
  nothing checks monotonicity. Harmless while ordering rests on `seq`
  (it does), but any future consumer sorting/filtering by `ts` inherits
  clock lies. Document "ts is informational only" in receipts.py. **S**.

#### F-20 — Floats at the result boundary reintroduce the drift D-003 banished
- `RunResult.total_cost` and per-decision `cost` are `float(route.cost)`.
  The ledger stays exact only because it re-derives
  `Decimal(str(float))` from shortest-repr strings. A high-precision
  cost (`"0.123456789012345678"`) loses digits at the float boundary, so
  ledger totals can diverge from true Decimal sums; tests assert totals
  with `assertAlmostEqual`, tolerating the drift instead of pinning it.
  An infinite route cost yields `Infinity` tokens in exported JSONL —
  invalid strict JSON. Carry Decimal through RunResult/decisions;
  serialize money as strings in receipts. **S–M**.

#### F-21 — API robustness warts at the authority/cost boundary
- `set_permission` with an unknown level *string* raises bare `KeyError`,
  not `AuthorityError`; empty-string capability names are settable;
  `ScopeContract(budget="abc")` raises `InvalidOperation` at
  construction (a crash, not a fail-closed run outcome); a `Decimal("NaN")`
  route cost detonates inside `min()` during routing. Each is small;
  together they mean malformed governance inputs produce tracebacks
  instead of receipted refusals — the opposite of the kernel's stated
  posture. Validate at the boundaries and raise domain errors. **S**.

#### F-22 — Reuse check: substring matching over caller-supplied registry
- Hits are `key.lower() in task/scope` substring matches: a registry key
  of `"a"` hits everything; a registry *path* is read and `json.loads`'d
  without size limits. Impact is bounded today because hits are advisory
  and receipted as INFERENCE-grade ("a hit never widens scope") — the
  failure mode is an owner misled by a poisoned registry into skipping
  needed work, i.e., a social-engineering assist, not a gate bypass.
  Word-boundary matching + a registry size cap close it. **S**.

---

## What I attacked and failed to break (verified positives)

These invariants were specifically targeted and **held** under code
tracing and the existing tests:

1. **CONTENT CANNOT GRANT AUTHORITY, via the dial.** A task stuffed
   with authorization claims leaves the dial unset and the run DENIED;
   `set_permission` rejects `requester` and `content` principals. The
   injection path creates *no* authority. (The hole is F-01 — minting
   an "owner" — not the content path.)
2. **CAPABILITY ≠ AUTHORITY, both directions.** Held-without-dial →
   DENIED; dial-without-held → DENIED; unset dial fails closed; NEVER
   denies. All four branches are in the supervisor loop in the right
   order and are test-covered.
3. **Budget halts at the exact step, on the happy path.** Decimal math,
   debit only on execution, no charge for subtracted/denied/halted
   steps, prior receipts intact, BUDGET_HALTED before the step runs.
   (The breaks are in the inputs — F-03/F-04 — not the arithmetic.)
4. **Cheapest-capable routing never picks an under-tiered route.**
   The tier filter is applied before the cost minimum; tie-breaking is
   deterministic (cost, tier, name).
5. **ASK_FIRST does not execute.** The step is not run, not charged,
   later steps are never mediated, and the halt is receipted.
6. **Per-step subtraction is safe.** Subtracted steps are not routed,
   not charged, and do not halt the run.
7. **Negative Step Zero blocks a problem-less run at intake** before
   any step is mediated.
8. **Naive receipt tampering is detected at the first bad index.**
   Field edits, swaps, mid-chain deletion, and forged appends with a
   wrong `prev_hash` all fail verification, at the right index, for
   the right reason. (F-02 is about an attacker who *recomputes* —
   a different, stronger adversary.)
9. **Stored receipts are frozen at append.** `copy.deepcopy` in
   `ReceiptStore.append` means later mutation of the emitter's dicts
   cannot rewrite stored history through the API.
10. **SUCCESS is refused on an incomplete in-memory chain.** `_close`
    downgrades SUCCESS to BLOCKED if the structural chain check fails —
    the kernel will not label its own broken run a success.
11. **Evidence defaulting.** Unlabeled claims resolve to UNRESOLVED,
    never upward. (The hole is F-14 — *pre-labeled* claims — not the
    default.)

---

## Top 5 strengthenings, in priority order

1. **Make the owner unforgeable.** Bind `Authority` to an owner-held
   secret (token/HMAC key) required by `set_permission`; until built,
   record in DECISIONS.md that `Principal` is assertion, not
   authentication. (Fixes F-01; precondition for trusting F-05 fixes.)
   **Size: M.**
2. **Key the evidence chain and anchor its head.** HMAC the record
   hash under the owner key, hash the *whole* record (not four
   fields), and emit a signed head `(last_hash, count)` at every
   Closeout to a separate owner-held location; add the monotonic run
   registry as an accident tripwire. External checkpointing (Commons
   / git) as a follow-up. (Fixes F-02, most of F-11.) **Size: M.**
3. **Restore the budget as an owner-owned invariant.** Contract budget
   is the ceiling; run parameters may only lower it; no-ceiling runs
   need an explicit receipted owner waiver; validate budget/costs/
   tiers as finite and in range at construction (kills NaN/Infinity/
   negative-cost escapes in one move). (Fixes F-03, F-04, parts of
   F-20/F-21.) **Size: S.**
4. **Receipt the authority, snapshot it per run.** Intake receipts the
   dial snapshot (hash); the supervisor mediates against an immutable
   per-run snapshot; dial changes with a store attached append
   authority-change records. (Fixes F-05.) **Size: S–M.**
5. **Fail closed in the large: exception-safe closeout + store write
   discipline.** try/finally in `run()` producing an ABORTED Closeout
   on any exception; file-locked, fsync'd appends and torn-tail
   recovery in `ReceiptStore` before any second writer exists.
   (Fixes F-07, F-08.) **Size: M.**

Next three, when those land: per-step trace citations + SELF_ATTESTED
labeling (F-06, M); define ASK_FIRST resume as a linked new run in
DECISIONS.md before Slice 3 (F-12, S); proposer identity on steps and
label provenance on claims (F-13/F-14, S).
