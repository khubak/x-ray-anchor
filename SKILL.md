---
name: x-ray-anchor
description: "Generates an x-ray pre-audit readiness report for Rust/Solana/Anchor programs — overview, threat model (protocol-type profiling + Solana account-model vuln classes, temporal & composability risks), instruction/entry-point map, invariants, docs quality, test/fuzz analysis, and developer/git history. Anchor-first with native-Solana fallback. Triggers on 'x-ray-anchor', 'x-ray this anchor program', 'x-ray this solana program', 'pre-audit this program', 'audit readiness', 'readiness report', 'prep this program', 'summarize this program'."
---

# X-Ray Anchor

Generate an `x-ray/` folder at the project root containing all output files. Pipeline: 3 steps, always sequential. Target stack: **Rust / Solana / Anchor** (Anchor-first; degrades to native `solana-program` programs).

`$SKILL_DIR` = the directory containing this SKILL.md file. Resolve it from the path you loaded this skill from (e.g. if this file is at `/path/to/x-ray-anchor/SKILL.md`, then `$SKILL_DIR` = `/path/to/x-ray-anchor`).

## Progress tracking (MANDATORY)

Before doing anything else, call TodoWrite with these 3 todos (all `pending`):

1. `Phase 1: Enumerate & measure program`
2. `Phase 2: Read sources, classify instructions/accounts, synthesize invariants`
3. `Phase 3: Write x-ray report files`

Transitions (update via TodoWrite — never batch):
- Mark Phase 1 `in_progress` immediately, before running `enumerate.sh`.
- When Step 1's parallel batch returns, in ONE TodoWrite call mark Phase 1 `completed` and Phase 2 `in_progress`.
- When Step 2 (including 2b–2g) finishes, in ONE TodoWrite call mark Phase 2 `completed` and Phase 3 `in_progress`.
- After all Step 3 output files are written, mark Phase 3 `completed`.

Rule: exactly one todo is `in_progress` at any time.

## Step 1: Enumerate & Measure

If the user specifies a path, use it as project root. Otherwise use cwd. If no `Anchor.toml`/`Cargo.toml` at root, check one level deep.

**Source directory detection**:
- **Anchor** (preferred): `Anchor.toml` present → source lives in `programs/<name>/src`. Use `programs` as the src-dir root (the scripts recurse).
- **Native Solana** / Cargo workspace: no `Anchor.toml` but `Cargo.toml` with `solana-program`/`anchor-lang` → source in `src/` or `programs/`. Use `programs` if present else `src`.

**Run enumeration** (single Bash call — includes output directory creation):
```bash
mkdir -p [project-root]/x-ray && bash $SKILL_DIR/scripts/enumerate.sh [project-root] [src-dir]
```

The output has labeled `=== name ===` sections: `Toolchain`, `program_ids`, `Source`, `nSLOC` (+ `TOTAL`), `doc_comments`, `overflow_checks`, `init_if_needed`, `unchecked_accounts`, `unsafe_blocks`, `test_files`, `test_functions`, `rust_unit`, `ts_integration`, `litesvm_bankrun`, `trident`, `cargo_fuzz`, `proptest`, `kani`, `docs`, `commit`, and the `git_*` history sections.

**Immediately after**, launch ALL of the following in a single message (parallel):

**1. Coverage** (`run_in_background: true`) — best-effort; Solana coverage is frequently unavailable:
```bash
cd [project-root] && cargo llvm-cov --workspace --summary-only 2>&1 || echo "COVERAGE_UNAVAILABLE"
```
If `cargo-llvm-cov` is not installed, `anchor`/`solana` toolchains are missing, or the program needs `cargo build-sbf` to compile, this fails. That is EXPECTED — test *existence* is already captured by enumeration. Coverage failure does NOT mean tests are absent. Do not block on it.

**2. Git security analysis + JSON read** (foreground, single Bash call):
```bash
cd [project-root] && python3 $SKILL_DIR/scripts/analyze_git_security.py --repo . --src-dir [src-dir] --json x-ray/git-security-analysis.json 2>&1 && cat x-ray/git-security-analysis.json
```
The JSON has 7 sections: `repo_shape`, `fix_candidates`, `dangerous_area_changes`, `late_changes`, `forked_deps` (git/path/patch Cargo overrides), `tech_debt`, `dev_patterns`.

**3. Preload reference files** (3 parallel Read calls — must be in context before Step 2):
- `$SKILL_DIR/references/threats.md` — protocol-type profiles, temporal & composability threats
- `$SKILL_DIR/references/solana-vulns.md` — Solana/Anchor account-model vulnerability classes (used in Step 2d-sol)
- `$SKILL_DIR/references/templates.md` — output templates, entry-point template, invariant map, architecture guide

**4. Spec/whitepaper detection** (1 Glob: `**/{whitepaper,spec,design,protocol,architecture,overview,README,CLAUDE}*.{pdf,md}` excluding `node_modules/`, `target/`, `x-ray/`, `tests/`). Skip user-facing docs (tutorials, API refs, changelogs). Then size-aware handling:
- **Path A (≤5 docs, each ≤300 lines):** Include them as Read calls in Step 2's parallel message.
- **Path B (>5 docs OR any doc >300 lines):** Launch a single subagent (`model: "sonnet"`) reading ALL doc files, returning a structured extraction (max 200 lines):
  ```
  Read each doc file listed below. Extract ONLY security-relevant information into this format:
  Files: [list of doc file paths]

  ### Doc-Stated Global Invariants
  [Every invariant/constraint/guarantee the docs claim must hold globally across instructions. Routed to §2/§3/§4 of invariants.md by shape, NOT §1.]
  ### Actor Definitions
  [Each role/authority (boss, admin, upgrade authority, approver) with stated permissions and trust level]
  ### Trust Assumptions
  [What the protocol assumes about external programs, oracles, admins, the upgrade authority, token mints]
  ### Cross-System Flows
  [How value/data moves between instructions, PDAs, and CPIs]
  ### Economic Properties
  [Fee structures, pricing/NAV, reward mechanisms, bounded parameters, supply caps]
  ### Key Design Decisions
  [Explicit "we chose X over Y because Z" statements]

  Rules: Quote the source doc for each claim. Omit empty sections. Max 200 lines.
  ```
Tag all spec-derived claims in the report with `(per spec)`. Doc-stated global invariants feed Step 2g's doc-comment routing → §2/§3/§4 by shape, NOT §1.

ALL calls (coverage, git analysis, 3 reference reads, spec glob) MUST appear in the same message. Proceed to Step 2 without waiting for coverage.

## Step 2: Read Source Files + Entry Point Scan (SINGLE message, ALL tool calls parallel)

CRITICAL: Every tool call — Bash, Agent, Read, Grep — MUST be issued in ONE message so they run concurrently. This includes source reads, the entry-point scan, and any spec doc detected in Step 1.

### Scope Filtering
- Skip generated IDL, `target/`, `tests/`, `trident-tests/`, `.anchor/`.
- Skip vendored crates and re-exported third-party code.
- When uncertain, include it but exclude from the scope table.

### Path A: ≤20 source files (direct reads)
One Read call per file. Do NOT read README/docs/Cargo.toml (handled in Step 1).

**Extract per file:** module type (instruction handler / `#[derive(Accounts)]` struct / state account / util), account types & roles, value-holding account fields, CPIs (target program + signed/unsigned), fund flows (transfer/mint/burn/lamports), invariant doc-comments, `require!`/`require_*!`/`assert!`/`constraint =`, `init`/`init_if_needed`/`close`, `UncheckedAccount`/`AccountInfo`/`/// CHECK:` sites, **delta writes** (per handler: account fields and the symbolic delta applied — e.g. `Δ(state.total_supply) = +shares`, `Δ(position.amount) = +amount` — same-block only; SPL `mint_to`/`burn` resolved to the mint supply / token-account amount when unambiguous), **guard predicates** (every `require!`/`require_*!`/`assert!` and every Accounts `constraint =`/`has_one =`/`address =` that references an account field, quoted verbatim with line number; skip guards referencing only instruction args with no field tie-back), **enum/one-shot transitions** (every `require!(field == X); …; field = Y` recorded as `X@Lx → Y@Ly` — include one-shot latches like `require!(addr == default); addr = concrete`).

### Path B: >20 source files (parallel subagents)

**Tier 1 — Small files (≤120 lines):** Batch into a single Bash `cat` call.

**Tier 2 — Large files (>120 lines):** Group by subsystem. Launch **one subagent per subsystem** (`model: "sonnet"`, up to 5, max ~10 files each):
```
Read each file listed below and return a structured summary. Do NOT analyze — just extract facts.
Files: [list]
For EACH file:
### [filename]
- **Type**: instruction-handler | accounts-struct | state-account | library/util
- **Instructions defined**: [pub fn handlers, if this is the #[program] module]
- **Accounts structs**: [#[derive(Accounts)] struct names + their account fields with types]
- **Roles/Access**: [Signer fields; has_one=/constraint=/address=/#[access_control]; in-body require_keys_eq!/require! on stored roles]
- **State fields (value-holding)**: [account fields holding balances/supply/collateral/config]
- **CPIs**: [target program (SPL Token/Token-2022/Pyth/self-PDA/System), signed (invoke_signed) or not, program-id pinned (Program/Interface/address=) or raw AccountInfo]
- **Fund flows**: [transfer_checked / mint_to / burn / lamport moves; in/out direction]
- **Account-model signals**: [UncheckedAccount/AccountInfo/CHECK sites; init/init_if_needed/close; PDA seeds+bump; remaining_accounts; sysvar usage]
- **Invariants**: [require!/require_*!/assert!/constraint=, and doc-comment invariant claims]
- **Delta writes**: For EACH handler, account fields that change + symbolic delta (`Δ(acct.field) = +expr` / `-expr`). Only same-body pairs with no intervening unknown CPI. SPL _mint/_burn → supply/amount only when unambiguous.
- **Guard predicates**: Every require!/require_*!/assert! AND every Accounts constraint=/has_one=/address= referencing an account field. Verbatim + line. Skip arg-only guards.
- **Enum/one-shot transitions**: `require!(field == X); …; field = Y` → `X@Lx → Y@Ly`. Include one-shot latches.
- **Function-level access map** (REQUIRED for the #[program] module): every instruction handler with its access — signer(s) + constraint, or [PERMISSIONLESS]. For permissionless ones, list the CPIs they make.
```

### Entry Point Grep Scan (INCLUDED in the same parallel message as source reads)

Solana entry points are **instruction handlers**. Run these in the SAME message as the source reads (POSIX ERE — portable across GNU/BSD grep and ripgrep):

```bash
# Anchor: locate the #[program] module file(s)
grep -rln '#\[program\]' [src-dir]/ --include='*.rs'
```
```bash
# Anchor: every instruction handler is a `pub fn` inside the #[program] module.
# Grep all pub fn (covers multi-line signatures where ctx: Context<...> is on a later line),
# plus the Context<Struct> type that names the Accounts struct to classify.
grep -rnE '^[[:space:]]*pub fn [A-Za-z0-9_]+' [program-module-file] ; \
grep -rhoE 'Context<[A-Za-z0-9_]+>' [program-module-file] | sort -u
```
```bash
# Native (non-Anchor) fallback, only if no #[program] found: the dispatcher + instruction enum.
grep -rnE 'entrypoint!|process_instruction|fn process' [src-dir]/ --include='*.rs' ; \
grep -rnE 'enum [A-Za-z0-9_]*Instruction' [src-dir]/ --include='*.rs' -A40
```

Within a `#[program]` module, **every `pub fn` is an instruction handler** (entry point) — they take `ctx: Context<...>` as the first parameter. The `Context<Struct>` type names the `#[derive(Accounts)]` struct to read for access classification. For native programs, entry points are the variants of the instruction enum dispatched in `process_instruction`.

ALL tool calls (source reads/Bash/subagents, ALL grep scans) MUST be in ONE message. Do NOT read test files or docs here.

### Step 2b: Entry Point Classification

Using the grep results + the Accounts struct definitions, classify ALL instruction handlers. Do NOT rely solely on subagent summaries — read the actual `#[derive(Accounts)]` struct and the handler body.

**For each instruction handler, read its `Context<Struct>` Accounts struct and the body, then classify into:**

1. **Permissionless** — no signer is bound to a stored role and no in-body `msg.sender`-equivalent check. The actor is a `Signer` but any address can sign (e.g. `user: Signer`). Note runtime gates that still apply (kill switch via `constraint = state.is_killed == false`, approval signature, `Clock` window) — they do not make it role-gated. You MUST read the Accounts struct + body before classifying permissionless.
2. **Role-gated** — a `Signer` is tied to a stored role via `has_one = role`, `constraint = signer.key() == state.role`, `address = ROLE_PUBKEY`, `#[access_control(...)]`, OR an in-body `require_keys_eq!(signer.key(), state.role)` / `require!(signer.key() == state.pending_x)`. Record which role. **The two-step authority transfer accept** (`accept_boss`-style: no modifier, but `require!(new_boss.key() == state.proposed_boss)`) is role-gated, not permissionless.
3. **Admin-only** — gated to the top authority (boss / `DEFAULT`-style admin / upgrade authority / Squads multisig). Record it.
4. **Query / read-only** — Solana has no `view`; an instruction that writes no persistent state (no `mut` account is mutated, typically returns a value / emits an event). Track separately — still executes on-chain.

Note: a reentrancy/CPI guard is NOT access control. `init`/`init_if_needed` are deployment/lifecycle — track separately.

**For each entry point, record:** program + handler name; access level (permissionless / role / admin / query); signer(s); caller (User, Boss, Admin, Approver, Keeper); parameters with trust level (`(user-controlled)`, `(user-signed)`, `(approver-signed)`, `(keeper-provided)`, `(protocol-derived)`); CPI chain (`→ token_interface::transfer_checked (Token-2022) → …`); accounts/state modified; value flow (`in`/`out`/`mint`/`burn`/`none`); reentrancy/hook surface.

This feeds the **permissionless** subset into x-ray.md Section 2 and the full set into entry-points.md (Step 3c).

The grep + Accounts-struct reading is a **hard gate**: the permissionless list in the report must match this verified list, not subagent summaries. On conflict, the grep + code reading wins.

### Step 2b-flow: Instruction Flow Path Construction

Using the entry-point data, construct flow paths for entry-points.md (NOT a separate analysis pass). For each major user-facing instruction:
1. Identify its `require!`/`constraint` preconditions and account-field checks.
2. For each, find which handler WRITES that field (known from the "state modified" field of other handlers) or which init creates that account.
3. Chain backwards: destination ← writer/initializer of its precondition ← … ← deployment.
4. Note non-call preconditions (Clock/time passage, kill-switch state, approval signature, PDA existence) with `◄──`.

**Output**: arrow chains grouped by actor. 15-30 lines. See the entry-points.md template.

### Step 2c: Backwards-Compatibility / Dead Code Detection

Watch for remnants of a removed mechanism. Signals: empty/trivial handler bodies, account fields declared but never meaningfully read/written, comments with "deprecated"/"legacy"/"no longer used", handlers that exist only to satisfy an interface and always return defaults, fields preserved solely for account-layout compatibility across an upgrade.

After reading ALL source, verify candidates (batch ALL caller-check Greps into a SINGLE message):
1. **Caller check (REQUIRED)**: no active caller / CPI / client reference. If still called, it's current design.
2. **Doc-comment check (REQUIRED)**: if a comment documents the behavior as intentional ("by design", "kept for layout"), it's intentional, not dead code.
3. **Layout obligation**: a field kept for account-size/layout compatibility across an upgrade is structural, not a remnant.

Only classify as backwards-compat when ALL of: no active callers, no doc-comment justifying it, and git history shows the mechanism it belonged to was removed. Note such code in Section 1; omit the subsection if none survive verification.

### Step 2d: Centralization & Pause/Kill-Switch Coverage

For each privileged role (boss, admin, redemption_admin, upgrade authority, mint authority, keeper):
1. List every operational action (from the function-level access map).
2. For each, note whether a multisig (Squads), timelock, or program-PDA gating exists. Distinguish authority-*transfer* delays (two-step propose/accept) from operational-*action* delays — a transfer delay does NOT protect against a compromised holder using instant operational functions.
3. Identify actions that extract/redirect user funds or mint supply (`mint_to`, vault withdraw, `set_*` of mint/oracle, `close_state`), and **who holds the upgrade authority** (an upgrade can replace all logic).

**Pause/kill-switch coverage** — for each critical state-changing instruction, check whether the kill switch / pause guard applies (`constraint = state.is_killed == false` or equivalent). Note which instructions bypass it.

Integrate into: **Actors table** (instant vs gated; upgrade & mint authority), **Trust Boundaries** (what each boundary actually protects, esp. upgrade authority blast radius), **Key Attack Surfaces** (frame as "[Role] compromise" / "Upgrade authority blast radius"). **Do NOT create a standalone "Centralization Risks" subsection.**

### Step 2d-sol: Account-Validation Scan (Solana-specific)

Using `references/solana-vulns.md` (preloaded in Step 1), walk the **Quick Scan Checklist** for each instruction handler + its Accounts struct. For each, flag classes whose detection signals are present AND whose mitigating constraint is absent. Prioritize the `UncheckedAccount` / `AccountInfo` / `/// CHECK:` sites surfaced by enumeration (`unchecked_accounts` count) — each is where Anchor's automatic owner/type/signer checks were turned off and made manual.

Check per handler: signer present & bound to role · state accounts typed (`Account<T>`/`AccountLoader<T>`) vs raw · PDA canonical `bump` & collision-free `seeds` · CPI target program-id pinned · `close =` vs manual close (revival) · duplicate same-type mutable accounts · `init_if_needed` reinit guard · account `.reload()` after mutating CPI · sysvars typed/`address =` constrained · checked/saturating math + `overflow-checks` (from enumeration) · `remaining_accounts` validated · token mint/authority constrained + Token-2022 fee/hook handling · rounding direction · input range checks.

These feed **Key Attack Surfaces** (Section 2) framed by class, obeying the DO-NOT-EXPLOIT rule. The account-model classes are first-class surfaces when their signals are present — do NOT bury them under protocol-type concerns.

### Step 2e: Protocol Classification

Classify the protocol following `references/threats.md` (type detection + hybrid classification, phase detection, CPI/external-call classification). Solana protocols are often custom hybrids (RWA/NAV, stake-pool, etc.).

### Step 2f: nSLOC

Use the exact nSLOC TOTAL from the Step 1 enumerate output (no `~` prefix) in the report header and scope table.

### Step 2g: Invariant Synthesis

Using the delta writes, guard predicates (including Accounts `constraint =`/`has_one =`), enum/one-shot transitions, and invariant doc-comments from Step 2, walk the taxonomy to produce invariant candidates. Reasoning pass — no new tool calls except the Grep batch in step 2 Pass B.

**Terminology**: a *guard* is a per-call precondition at a single callsite (`require!(amount >= MIN)`, or an Accounts `constraint`). Not a falsifiable invariant. An *invariant* must hold globally across any sequence of instructions. Guards feed §1 of `invariants.md`. Invariants *lifted* from guards (step 2) or stated in doc-comments feed §2/§3/§4.

**Doc-comment routing** (run before the structural walk): for each `///`/`//!` asserting a global property (e.g. *"total supply never exceeds max_supply"*, *"fee never exceeds 10_000 bps"*, *"only one active offer per token pair"*), route DIRECTLY to §2 (or §3/§4 if cross-program/derived) by shape (Conservation/Bound/Ratio/StateMachine/Temporal). Source tag: `DocComment: file.rs:LN`. Do NOT place doc-stated global invariants in §1. Then still run the structural scans — they confirm (On-chain=Yes) or contradict (On-chain=No).

**Walk order** (each step uses raw extraction data):

1. **Conservation scan**: delta-write pairs where `Δ(A) = +expr` and `Δ(B) = -expr` in one handler. Mapping/account-field counterpart → `A == Σ B[key]`. Token mint/burn paired with a tracked supply field → conservation. Verify across ALL handlers that write either field — if any writes one without the other, split into Yes/No rows ("partial conservation"). **Negative conservation**: a handler that *ought* to track a flow (vault in/out, mint/redeem) with zero field Δ is itself an observation.

2. **Guard/constraint extraction and lift** (two passes over each `require!`/`require_*!`/`assert!`/Accounts `constraint =`):
   - **Pass A — Extract verbatim (§1)**: every guard becomes a `G-N` row. Quote verbatim + location. Include Anchor `constraint =`/`has_one =`/`address =`. Mechanical dump of per-call preconditions. Skip arg-only guards with no field tie-back and no global implication.
   - **Pass B — Lift, then check all write sites**: does the guard imply a property holding across any sequence? If NO (only constrains a transient arg) → leave in §1. If YES (implies a persistent property — `require!(amount >= MIN)` ⇒ "every active position ≥ MIN"; `constraint = fee <= 10_000` ⇒ "fee ∈ [0,10_000]") → rewrite as a global property and locate ALL write sites of the constrained field via Grep. Batch ALL write-site Greps into a SINGLE message. If ALL write sites enforce an equivalent guard → §2 Bound, On-chain=**Yes**. If ANY write site lacks it → §2 Bound, On-chain=**No**, cite the unguarded site (high-signal: simultaneously an invariant and a candidate bug). Include `set_*` admin setters writing a bounded field.

3. **Ratio scan**: each field written as `A = B * C / D` (B,C,D fields or snapshots). Note rounding direction and snapshot ordering (before/after other writes — matters for price/share math).

4. **State machine / one-shot scan**: each enum/uint/Pubkey field in `require!(field == X); … field = Y`. Distinguish one-shot latch (no path back, e.g. set mint authority), togglable flag (another handler flips it back — e.g. kill switch enable/disable — NOT a state-machine invariant, skip), cyclic state (record as a cycle).

5. **Temporal scan**: each `Clock::get()?.unix_timestamp`/`.slot`/`.epoch` comparison against a stored field (deadline, last_update, duration). Note checked-then-updated (safe) vs updated-then-checked (stale-read risk).

6. **Cross-program / cross-account scan**: each CPI whose result is used in arithmetic or a field write — record the caller assumption (esp. **token transfer amount under Token-2022 fees**: does the code assume received == requested?), then the callee/other-account write site or documented behavior. If it can change independently → §3, On-chain=No. Include sysvar-derived assumptions and setter-vs-invariant mismatches. Only rows where BOTH sides are in scope (a CPI callee may be cited by its documented SPL interface — flag the assumption explicitly).

7. **Economic derivation**: check if combinations of §2/§3 invariants imply a higher-order property. Each economic invariant cites the specific `I-N`/`X-N` IDs. If any source is On-chain=No, the economic invariant is too.

**Verification gate** (MANDATORY before including any inferred invariant): confirm the Δ-pair / verbatim guard / lifted-property-references-persistent-field-and-all-write-sites-enumerated / exact ratio + snapshot ordering / both edge sides + no reverse path / Clock-vs-field temporal / both cross sides in scope / referenced IDs verified. If you cannot verify → drop the row. "Could not verify" is not a valid row.

**Output**: candidates feed `invariants.md` (Step 3a). x-ray.md Section 3 is a POINTER ONLY (counts + link).

## Step 3: Write Output

### Test existence vs. coverage execution (CRITICAL)

**Test presence** is from Step 1 enumeration (`test_files`, `test_functions`, `rust_unit`, `ts_integration`, `litesvm_bankrun`, `trident`, `cargo_fuzz`, `proptest`, `kani`). These are file-scan results and ALWAYS reliable regardless of whether the toolchain compiles or runs. Multi-signal categories (`trident`, `cargo_fuzz`, `kani`) output as `functions:configs`.

**Coverage metrics** come from `cargo llvm-cov`, which needs installed tooling and a host-compilable build. On Solana this is frequently unavailable (no `anchor`/`solana`/`cargo-llvm-cov`, or BPF-only build). Rules:
1. Use `test_files`/`test_functions`/the fuzz counts for ALL test-existence claims. Never infer "no tests" from coverage failure.
2. If coverage fails but tests exist, report: `"[N] test files with [M] test functions detected (Trident fuzz: X, bankrun/litesvm: Y); coverage metrics unavailable — [reason]"`.
3. In "Gaps", only flag missing categories (trident=0, cargo_fuzz=0, proptest=0, kani=0, integration=0). Prioritize: missing stateful fuzz (Trident) + formal (Kani) for math/accounting is higher priority. Note absence of **negative tests** (unauthorized signer / wrong owner / substituted account) — Solana's core bug class.
4. Never claim "commits without tests" from coverage failure. `test_co_change_rate` measures file co-modification, not coverage — qualify it.
5. Coverage failure must NOT cascade into the threat model or verdict.

Check coverage status: include if done, failure reason if failed, "pending" if still running. Do NOT wait.

### 3a. Write ALL output files (4 parallel Write calls in ONE message)

All files go into `x-ray/`. Write ALL FOUR in a SINGLE message:

**1. x-ray/architecture.json** — Follow the architecture guide in `references/templates.md`. Nodes: `actor` (signers/roles), `protocol` (in-scope program/PDAs/instruction groups), `external` (CPI targets: SPL Token/Token-2022, Pyth/Switchboard, System program, DEX/stake pools). Edges = CPIs / signer authority / token movement.

**2. x-ray/x-ray.md** — Follow the output template. Under 500 lines. No fabrication. Section 3 (Invariants) is a **POINTER ONLY** to `invariants.md` (one blockquote with counts + strong link). Do NOT include a guards table or top-invariants list in x-ray.md.

**Key Attack Surfaces cross-link requirement**: cross-reference each surface against the `invariants.md` blocks. If a surface's cited `file:line` falls within the `Location`/`Derivation`/`Caller side`/`Callee side` window of any `G-N`/`I-N`/`X-N`/`E-N` block, append matching IDs as LOWERCASE-slug markdown links: `- **Surface** &nbsp;&#91;[X-4](invariants.md#x-4), [I-17](invariants.md#i-17)&#93; — …`. Separate surfaces with a blank line. Account-validation/upgrade-authority surfaces may be unlinked — healthy, not a gap.

**3. x-ray/entry-points.md** — Using the full Step 2b data + Step 2b-flow paths, follow the entry-points template. Start with Instruction Flow Paths, then Permissionless / Role-Gated / Admin-Only / Query / Initialization sections. Factual only. If >30 instructions, use compact tables for role-gated/admin; permissionless and query get detail blocks.

**4. x-ray/invariants.md** — Follow the invariant map template. Four sections: Enforced Guards (incl. Anchor constraints), Inferred (Single-Account/Program), Inferred (Cross-Program/Account), Economic. **Use `#### G-N`/`#### I-N`/`#### X-N`/`#### E-N` heading blocks — NOT tables** (heading anchors are cross-file link targets). Every inferred block cites a concrete Δ-pair, guard/constraint-lift + write-sites, edge, Clock predicate, or doc-comment. Cross blocks cite BOTH sides. Factual only.

**Writing Section 2 (Threat & Trust Model)** — Follow the output template. Use `references/threats.md` for protocol-type/temporal/composability content and `references/solana-vulns.md` for account-model surfaces. For hybrids, merge adversary lists (primary first, de-duplicate).

**Verification rules** (apply during Section 2):
- **Permissionless entry points**: use only the grep + Accounts-struct-verified list from Step 2b.
- **Security claims**: before claiming a check is missing/bypassable, trace the data flow — identify all write sites of the field (Grep) and confirm against them, and confirm the Accounts struct doesn't already enforce it via a `constraint`. If you cannot verify, qualify with "could not confirm".

**Section 6 (Git History)**: integrate `x-ray/git-security-analysis.json` into Contributors, Review Signals, Hotspots, Security-Relevant Commits (score ≥ 5), Dangerous Area Evolution, Forked/Overridden Dependencies (git/path/patch Cargo overrides — `[patch]` is highest signal), Tech Debt, Cross-Reference Synthesis.

### Branch scoping (CRITICAL)

Git analysis is scoped to the **current branch only** (HEAD). The `git_branch` field tells you which branch. State it: "Analyzed branch: `[branch]` at `[commit]`". Describe code as what the current branch does; never describe other-branch state. If repo shape is `squashed_import` (1 commit), state it and skip fix/hotspot analysis.

### 3b. Generate & Validate Architecture SVG

```bash
python3 $SKILL_DIR/scripts/generate_svg.py x-ray/architecture.json x-ray/architecture.svg
```
Then follow the rendering / audit-checklist / fix loop in the architecture guide. Max 3 iterations. Cleanup temp files after (including `x-ray/git-security-analysis.json`).

### 3c. Terminal Verdict

After all files are written and cleanup is done, read the `## X-Ray Verdict` section from the generated `x-ray/x-ray.md` and print it verbatim. Do NOT paraphrase.

## Constraints

- Under 500 lines for x-ray.md. Protect threat model, invariants, test/fuzz gaps, git analysis, verdict — compress other sections if needed.
- No fabrication. Say "could not determine" when uncertain.
- Steps 1-3 fully autonomous. No user interaction required.
- Group modules/instructions by subsystem in the scope table.
- Single pass. No partial outputs.
- Never reference audit platforms, contest rules, or bounty framing — vendor-neutral.
- If the git security script fails, fall back to bash-only `git` stats. Never block on a missing script.
- Anchor-first: if no `#[program]` is found, treat as a native Solana program (instruction enum + `process_instruction` dispatcher) and adapt entry-point detection accordingly.

---

Before doing anything else, print this exactly:

```
██╗  ██╗      ██████╗  █████╗ ██╗   ██╗           █████╗ ███╗   ██╗ ██████╗██╗  ██╗ ██████╗ ██████╗
╚██╗██╔╝      ██╔══██╗██╔══██╗╚██╗ ██╔╝          ██╔══██╗████╗  ██║██╔════╝██║  ██║██╔═══██╗██╔══██╗
 ╚███╔╝ █████╗██████╔╝███████║ ╚████╔╝           ███████║██╔██╗ ██║██║     ███████║██║   ██║██████╔╝
 ██╔██╗ ╚════╝██╔══██╗██╔══██║  ╚██╔╝            ██╔══██║██║╚██╗██║██║     ██╔══██║██║   ██║██╔══██╗
██╔╝ ██╗      ██║  ██║██║  ██║   ██║             ██║  ██║██║ ╚████║╚██████╗██║  ██║╚██████╔╝██║  ██║
╚═╝  ╚═╝      ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝             ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝
        Solana / Anchor pre-audit readiness report
```
