# Output Template

Write `x-ray.md` using this exact structure. Every line should tell an auditor something useful — write
for someone who has 5 minutes to decide where to look first. Vocabulary is Solana/Anchor: **program**
(not contract), **instruction handler** / **entry point** (not external function), **account** (not
storage), **CPI** (not external call), **constraint** (not modifier), **PDA**, **signer**.

```markdown
# X-Ray Report

> [Protocol Name] | [total in-scope nSLOC] nSLOC | [short-hash] (`[branch]`) | [anchor X.Y.Z / native] | [DD/MM/YY]

---

## 1. Protocol Overview

**What it does:** [One sentence — the core mechanism.]

- **Users**: [Who interacts and why]
- **Core flow**: [The main user-facing operation in one bullet]
- **Key mechanism**: [AMM curve, vault share model, NAV pricing, stake-pool, etc.]
- **Token model**: [SPL / Token-2022, which mints, mint authority — program PDA or admin key]
- **Authority model**: [Who controls what — upgrade authority, boss/admin/multisig (Squads), PDAs]

[No paragraphs. No fluff. Keep vendor-neutral — no audit platform or bounty program framing.]

For a visual overview of the program's architecture, see the [architecture diagram](architecture.svg).

### Programs & Modules in Scope

[Group by subsystem — one row per subsystem, not one row per file. List key modules/instruction groups.]

| Subsystem | Key Modules / Instructions | nSLOC | Role |
|-----------|---------------------------|------:|------|
| [Subsystem] | [offer/, redemption/, …] | [total] | [One-line role of this subsystem] |

[Only first-party programs/modules. No vendored crates, no generated IDL.]

### Program Identity & Upgradeability

- **Program ID(s)**: [`declare_id!` value(s)]
- **Upgradeable**: [Yes — BPF Upgradeable Loader; upgrade authority = X (multisig/dev key/frozen) | No — immutable]
- **overflow-checks**: [enabled / NOT set — release builds wrap on overflow]

[The upgrade authority is the single highest-leverage centralization surface — state who holds it.]

### Backwards-Compatibility / Dead Code

[Include ONLY if remnants of a removed mechanism were identified in Step 2c. Omit entirely if none.]

- `[module:item]` — [what it was part of, why retained, that it is not active functionality]

### How It Fits Together

[Start with "The core trick:" — one sentence on the fundamental mechanism.]

[Then 3-5 key flows as annotated code-block diagrams. Each flow gets:]
[1. A ### subheading]
[2. A code block showing the call chain with tree-style branching (├─ └─), including CPIs]
[3. Italic annotations on critical steps (where account state changes, where a CPI fires, where a signer/
PDA authority is used, where tokens move)]
[Keep to the 3-5 MOST IMPORTANT user-facing flows. Skip admin/governance flows — those are Section 2.]

[IMPORTANT: Use concrete program/module names in chains, NOT trait/interface names. Write
`offer::take_offer → token_utils::execute_token_operations → token_interface::transfer_checked (CPI →
Token-2022)`. Name the actual program a CPI targets (SPL Token / Token-2022 / Pyth / the program's own
PDA-signed CPI).]

[Focus on flows that span multiple instructions/CPIs — where integration bugs hide. No use/import lists.]

---

## 2. Threat & Trust Model

> **Bullet brevity rule (every bullet-heavy subsection in Sections 2, 3, 6):** one tight sentence per
> bullet — ideally one line, max two. Don't restate what the `file:line` reference already shows.
>
> ✅ `**Unconstrained CPI target** — take_offer.rs:129 token_in_program is Interface<TokenInterface>; verify every token CPI pins the program id and the mint's owner matches it.`
>
> ❌ Not a multi-sentence paragraph re-explaining what the code line already says. Code refs carry the
> evidence — prose must not duplicate them.

### Protocol Threat Profile

> Protocol classified as: **[Primary type]** with **[Secondary type(s)]** characteristics

[1-2 sentences on why, based on code signals. For hybrids, merge adversary lists: primary first, then
unique secondary threats, de-duplicated.]

### Actors & Adversary Model

| Actor | Trust Level | Capabilities |
|-------|-------------|-------------|
| [Role] | [Trusted / Bounded (reason)] | [What they can do — instant vs delayed] |

[Only named roles from code (boss, admin, redemption_admin, approver, upgrade authority, keeper, user).
Never "Anyone" as a row; never "Semi-trusted" — use "Bounded (reason)".]

[CENTRALIZATION INTEGRATION: be specific about instant vs timelocked/multisig. State who holds the
**upgrade authority** and the **mint authority** (program PDA vs admin key). If a role's actions bypass
the kill switch / pause, note it. This replaces any standalone "Centralization Risks" section.]

[CELL BREVITY: summarise many powers, e.g. "boss: 11 instant setters incl. set_kill_switch(disable),
configure_max_supply, set_onyc_mint, close_state, mint authority moves. No timelock; gated only by boss
signer." ≤2 lines per cell.]

**Adversary Ranking** (ordered by threat level for this protocol type, adjusted by git evidence):

1. **[Adversary type]** — [1 sentence: WHO and WHY relevant to this protocol type.]
2. ...

[3-5 entries. ONE sentence each — WHO threatens the protocol. HOW/WHERE belongs in Key Attack Surfaces.]

[Reference: "See [entry-points.md](entry-points.md) for the full permissionless entry-point map." Do NOT
list permissionless entry points here.]

### Trust Boundaries

[Where trust transitions. For each: what's trusted, damage if compromised, whether multisig/timelock/PDA
gating exists.]
[For the **upgrade authority** boundary: state exactly what it protects and its blast radius — an upgrade
can replace all logic. For mint authority: program-PDA-held vs key-held.]
[If git analysis shows a boundary's code was frequently modified or fix-scored, note: "*Git signal: N
modifications, M fix-scored commits — elevated risk.*"]

[Per-bullet: `**Boundary** — protection status + worst instant action it leaves open + code ref; max 2 lines.`]

### Key Attack Surfaces

[The SINGLE authoritative location for attack-surface details. Adversary Ranking says WHO; this says WHERE.]
[Sorted by priority (protocol-type relevance + account-model risk from solana-vulns.md + git hotspot + fix
history + late changes). NOT alphabetical.]
[Investigation pointers, not exploit writeups. No RISK labels, no mitigation analysis, no per-surface git
evidence.]

- **[Surface name]** &nbsp;&#91;[X-N](invariants.md#x-n), [I-N](invariants.md#i-n)&#93; — [one tight sentence: code ref + the concern (what's unusual/fragile/worth double-checking) + what to trace. 1 line, max 2.]

[Separate bullets with a blank line. Hard cap 2 lines per surface.]

[**INVARIANT CROSS-LINK RULE**: if a surface's code location falls within the derivation window of any
G-/I-/X-/E- block in `invariants.md`, append the matching IDs as lowercase-slug markdown links
(`invariants.md#x-4`). Surfaces that are purely account-validation or upgrade-authority concerns may be
left unlinked — that is healthy, not a gap.]

[**DO-NOT-EXPLOIT RULE (critical):** describe the *concern area*, not the exploit. If a bullet contains
"→ attacker drains X", "→ funds frozen", "double-counts", "mints unbacked" — cut it. Replace with "Worth
checking…", "Worth tracing…", "Worth confirming…". Name the asymmetry / missing check / unusual pattern,
then stop.]

[FRAMING RULE: name surfaces after the root threat area, not symptoms. "Unconstrained CPI program
accounts" is a surface — an individual `AccountInfo` token program is evidence inside it. "Upgrade
authority blast radius", "boss operational powers without timelock", "Token-2022 transfer-fee accounting"
are surfaces. Account-model classes from `solana-vulns.md` (missing signer, PDA bump, account close,
init_if_needed) are first-class surfaces when their signals are present.]

[Example of the pattern to follow:]

[✅ `- **Manual close paths** — close_state.rs:120-150 drains lamports and zeroes state manually rather than via Anchor close=; worth confirming data is zeroed and the account can't be revived/re-init.`]

[❌ Not: `- **close_state revival** — refunds lamports without zeroing → attacker tops up the account and reuses stale boss field → takeover.` (spells out the exploit chain).]

### Upgrade & Authority Architecture Concerns

[Include if the program is upgradeable or uses privileged authorities/PDAs.]

- **[Concern]** — [one tight sentence: code ref + risk + affected accounts. Max 2 lines.]

[Typical: upgrade authority not a multisig/timelock; mint authority held by a key vs program PDA;
two-step authority transfer correctness (propose/accept); PDA authority blast radius; placeholder/init
windows; `set_*` admins without delay.]

### Protocol-Type Concerns

[From the Section 2a classification. ONLY concerns NOT already in Key Attack Surfaces. Adds type-specific
technical detail (curve math, share rounding, NAV precision, funding) — not restated risks.]

**As a [Primary type]:**
- [One tight line: code ref + the technical concern. Max 2 lines.]

**As a [Secondary type]** *(if applicable)*:
- [Same format]

[2-3 bullets per type. Every bullet cites a specific module/instruction.]

### Temporal Risk Profile

[ONLY phases adding NEW info beyond Actors/Attack Surfaces/Upgrade Architecture. Typically Deployment &
Initialization adds value (init front-running, init_if_needed reinit, mint-authority-not-yet-moved);
Governance & Upgrade usually already covered. 1-3 bullets per phase, each citing code.]

**Deployment & Initialization:**
- [One tight line: code ref + risk + mitigation status. Max 2 lines.]

**Market Stress** *(include only if adding new info)*:
- [Same format — oracle staleness/confidence, CU/congestion, liquidation profitability]

**Deprecation** *(include only if V2/migration evidence exists)*:
- [Same format]

### Composability & Dependency Risks

**Dependency Risk Map:**

[Blockquote per significant CPI dependency:]

> **[External program — Pyth / SPL Token-2022 / a DEX / a stake pool]** — via `[module:instruction]`
> - Assumes: [price freshness / exact transfer amount / success / account state]
> - Validates: [staleness+confidence / mint+authority / balance-delta] or [NONE]
> - Program-id pinned: [typed Program/Interface / address= / RAW AccountInfo — arbitrary CPI risk]
> - Mutability: [Immutable / Upgradeable / Governed by X]
> - On failure: [revert / fallback / fail-open]

**Token Assumptions** *(unvalidated only)*:
- [Token-2022 transfer fee / hook / freeze / decimals]: assumes [assumption not validated] — impact if violated.

**Shared State Exposure** *(if applicable)*:
- [Shared pools/oracles/PDAs; delegations to program PDAs; deprecated PDAs holding funds.]

---

## 3. Invariants

> ### 📋 Full invariant map: **[invariants.md](invariants.md)**
>
> A dedicated reference file contains the complete invariant analysis — do not look here for the catalog.
>
> - **[N] Enforced Guards** (`G-1` … `G-N`) — per-call preconditions (`require!`/`constraint`) with `Check` / `Location` / `Purpose`
> - **[N] Single-Account/Program Invariants** (`I-1` … `I-N`) — Conservation, Bound, Ratio, StateMachine, Temporal
> - **[N] Cross-Program / Cross-Account Invariants** (`X-1` … `X-N`) — CPI caller/callee + cross-account assumptions
> - **[N] Economic Invariants** (`E-1` … `E-N`) — higher-order properties deriving from `I-N` + `X-N`
>
> Every inferred block cites a concrete account-field Δ-pair, guard/constraint-lift + write-sites, state
> edge, `Clock` predicate, or doc-comment quote. The **On-chain=No** blocks are the high-signal ones.
> Attack-surface bullets above cross-link into the relevant blocks (e.g. `[X-4]`, `[I-17]`).

[Section 3 is a POINTER, not a catalog. Fill the bracketed counts from the actual invariants.md output.]

---

## 4. Documentation Quality

| Aspect | Status | Notes |
|--------|--------|-------|
| README | [Present/Missing] | [path] |
| Rust doc comments | [~N: /// //! /** ] | [Coverage notes] |
| Spec/Whitepaper | [Present/Missing] | [path] |
| Inline comments / `CHECK:` discipline | [Sparse/Adequate/Thorough] | [Are `/// CHECK:` justifications present on every UncheckedAccount?] |

[Skip user-facing docs (tutorials, API refs). If a spec was ingested in Step 1, tag derived claims with
`(per spec)` vs `(per code)`. Note whether `/// CHECK:` comments actually justify each unchecked account.]

---

## 5. Test Analysis

| Metric | Value | Source |
|--------|-------|--------|
| Test files | [N] | File scan (always reliable) |
| Test functions | [N] | File scan (always reliable) |
| Line coverage | [N% or "Pending" or "Unavailable — [reason]"] | cargo llvm-cov (best-effort; often unavailable) |

[IMPORTANT: Test file/function counts come from file scanning and are always accurate. Coverage on Solana
is frequently unavailable (no `anchor`/`solana`/`llvm-cov` installed, build needs `cargo build-sbf`). If
coverage fails, this does NOT mean tests are absent — state this clearly.]

### Test Depth

| Category | Count | Modules Covered |
|----------|-------|-----------------|
| Rust unit (`#[test]`/`#[tokio::test]`) | [N] | [List or "none"] |
| Integration (litesvm / solana-bankrun / anchor-bankrun / solana-program-test / mollusk) | [N] | [List or "none"] |
| TS integration (anchor/bankrun, mocha/jest/vitest) | [N] | [List or "none"] |
| Fuzz — Trident | [N] | [List or "none"] |
| Fuzz — cargo-fuzz | [N] | [List or "none"] |
| Property — proptest / quickcheck | [N] | [List or "none"] |
| Formal — Kani / Certora-Solana | [N] | [List or "none"] |

[Only include rows where count > 0 or absence is notable. Always surface Fuzz (Trident at least) and
Formal even if 0 — their absence is audit-relevant. Multi-signal categories (trident, cargo_fuzz, kani)
come from enumerate as `funcs:configs` — report the function/target count and note config presence.]

### Gaps

[Only flag missing test categories — never claim "no tests" when enumeration found test files. Prioritize:
missing stateful fuzz (Trident) and formal (Kani) for math/accounting logic is higher priority than
missing integration. For account-model-heavy programs, note absence of negative tests (unauthorized
signer, wrong owner, substituted account) — Solana's core bug class.]

---

## 6. Developer & Git History

> Repo shape: [normal_dev / squashed_import] — [one sentence]

### Contributors

| Author | Commits | Source Lines (+/-) | % of Source Changes |
|--------|--------:|--------------------|--------------------:|
| [Name] | [N] | +[N] / -[N] | [N%] |

[Flag single-developer dominance (>90%), ghost contributors (1 commit), uneven distribution.]

### Review & Process Signals

| Signal | Value | Assessment |
|--------|-------|------------|
| Unique contributors | [N] | [Single-dev / Small team / Larger team] |
| Merge commits | [N] of [total] ([%]) | [Review process / No merge commits] |
| Repo age | [first] → [last] | [Duration] |
| Recent source activity (30d) | [N] commits | [Active / Quiet / Late burst before audit] |
| Test co-change rate | [N%] | [% of source-changing commits also touching tests — co-modification, NOT coverage] |

### File Hotspots

| File | Modifications | Note |
|------|-------------:|------|
| [path] | [N] | [High churn — prioritize review] |

[Top 5-10 most-modified source files.]

### Security-Relevant Commits

[Include ONLY if fix_candidates has entries with score >= 5. For squashed-import repos, skip and note
"No development history — fix detection not applicable."]

**Score** = weighted sum of fix-like signals: message keywords (fix, bug, overflow, signer, cpi, pda…),
diff structure (adds/removes `require!`/`constraint`, changes CPI/transfer or signature/seed handling,
touches accounting), and shape (focused = higher). **10+ warrants a manual diff.**

| SHA | Date | Subject | Score | Key Signal |
|-----|------|---------|------:|------------|
| [hash] | [date] | [subject] | [N] | [top reason] |

### Dangerous Area Evolution

[Include if normal development history.]

| Security Area | Commits | Key Files |
|--------------|--------:|-----------|
| [access_control / fund_flows / oracle_price / liquidation / signatures / state_machines] | [N] | [top 2-3 files] |

### Forked / Overridden Dependencies

[Include if forked_deps has git_dependencies, path_dependencies, or patch_overrides. Skip if all deps are
standard crates.io versions.]

| Crate | Source | Detail | Risk |
|-------|--------|--------|------|
| [name] | [crates.io / git / path / **patch**] | [version / url@rev / path] | [Notes] |

[**[patch] overrides are the highest signal** — a published crate silently replaced by a fork; upstream
security fixes won't auto-propagate. Git/path deps on `anchor-*`/`spl-*`/`pyth-*` mean the security-critical
base is a fork, not the audited release. Pinned `rev`/`branch` on a git dep = a moving or unaudited target.]

### Technical Debt Markers

[Include if tech_debt.total_count > 0. Types: TODO/FIXME/HACK/XXX/SAFETY/AUDIT/BUG.]

| File:Line | Type | Text | Author | Date |
|-----------|------|------|--------|------|
| [path:N] | [TYPE] | [text] | [blame author] | [date] |

### Security Observations

[4-8 bullets — each ONE line: `**Lead-in** — short fact + file/commit ref.`]
- [Single-developer risk if applicable]
- [Missing merge/review signals]
- [High-churn files]
- [Late changes before audit]
- [Fix commits without test co-change — note: measures co-modification, not coverage]
- [git/patch-overridden security-critical crates]
- [Tech debt in security-critical paths]

### Cross-Reference Synthesis

[2-4 bullets connecting git signals to Sections 2-3. One line each, use → to compress.]
- [e.g. "**take_offer_permissionless is #1 churn AND top attack surface** — repeated stack/permissionless fixes (47f4ac0, 4ddd3a6) → highest-leverage review."]

---

## X-Ray Verdict

**[TIER]** — [one sentence justification]

[Tier calculation: lowest level across Tests, Docs, Access Control (evidence in Sections 4-5). If Code
Hygiene has TODOs in security-critical paths OR overflow-checks is not set OR unjustified `CHECK:`
accounts dominate (Section 6/1), drop one tier. Absence of TODOs does NOT raise the tier.]

[Test tier from EXISTENCE (Step 1 file scan), NOT runtime pass/fail.]

[Tier thresholds:]
[Tests: EXPOSED=0 test functions, FRAGILE=unit/integration only, ADEQUATE=+ fuzz (Trident) OR property, HARDENED=+ stateful fuzz with invariants, FORTIFIED=+ formal (Kani/Certora)]
[Docs: EXPOSED=no doc comments + no spec, FRAGILE=sparse, ADEQUATE=doc comments present, HARDENED=+ spec, FORTIFIED=+ justified `/// CHECK:` on every unchecked account]
[Access Control: EXPOSED=unclear authorities / raw AccountInfo authority, FRAGILE=roles exist + key-held upgrade/mint authority, ADEQUATE=roles + boundaries clear, HARDENED=+ multisig (Squads) or timelock on upgrade, FORTIFIED=+ kill switch/pause + program-PDA mint authority]

**Structural facts:**
1. [Verifiable structural fact — e.g. "4.2K nSLOC across N modules / M instructions", "upgradeable, authority = dev key", "overflow-checks enabled", "83 UncheckedAccount/CHECK sites"]
2. ...
[3-5 items. ONLY measurable facts from Sections 1-6. No security claims, no bug hypotheses. The verdict
describes structural posture (tests, docs, access control, complexity) — NOT security.]
```
# Entry Point Map Template

Write `entry-points.md` using this structure. A purely structural reference — no threat analysis, no
invariants, no git history. It answers: "which instructions can be invoked, by whom (which signer/role),
and what accounts/tokens do they touch."

```markdown
# Entry Point Map

> [Protocol Name] | [N] instructions | [N] permissionless | [N] role-gated | [N] admin-only | [N] query

---

## Instruction Flow Paths

[Order instructions into expected execution flows — the "story" from deployment to steady state. Each
major user-facing instruction gets a path showing every step that must happen before it becomes callable
(account inits, authority setup, vault funding). Lets auditors see the full prerequisite chain.]

[Group by actor. Trace backwards from destination to deployment. Simple arrow chains. Annotate non-call
preconditions with `◄──`.]

[Example:]

### Setup (Boss)

`initialize()` → `transfer_mint_authority_to_program()` → `make_offer()` → `offer_vault_deposit()`  ◄── vault must be funded

### User Flow

`[boss setup above]` → `take_offer()`  ◄── kill switch off; approval sig if offer.needs_approval
                          └─→ `create_redemption_request()` → `fulfill_redemption_request()`  ◄── redemption_admin only

### Maintenance (Admin)

`set_kill_switch(true)`  ◄── boss or admin

[Rules: one chain per major destination; branch with `├─→`/`└─→`; reference earlier flows with
`[setup above]`; `◄──` for non-call preconditions (kill switch, approval signature, time/Clock,
PDA existence). 15-30 lines.]

---

## Permissionless

[Instructions callable by any signer with no effective role restriction. Sorted by value flow: tokens-in
first, tokens-out second, no-movement last. Note: an instruction can be permissionless yet gated by a
runtime condition (kill switch, approval signature) — record that.]

### `program::instruction_name()`

| Aspect | Detail |
|--------|--------|
| Signers | [which Signer accounts — `user`, etc.] |
| Access | [Permissionless — note runtime gates: kill switch / approval sig / Clock window] |
| Parameters | [param (user-controlled), param (approver-signed), param (protocol-derived)] |
| Accounts (key) | [the important accounts + types: `Account<State>`, `InterfaceAccount<TokenAccount>`, PDAs, `UncheckedAccount`/CHECK] |
| CPI chain | `→ token_interface::transfer_checked (Token-2022)` `→ …` |
| State modified | [account fields / mappings that change] |
| Value flow | [Tokens: user → boss / vault → user / mint / burn / None] |
| Reentrancy / hook surface | [Token-2022 transfer hook? state-after-CPI?] |

[Repeat for each permissionless instruction.]

---

## Role-Gated

[Instructions restricted by an account constraint to a stored role (`has_one`, `constraint`,
`require_keys_eq!`, in-body signer check). Group by role (boss / redemption_admin / approver / keeper).]

### `redemption_admin`

#### `program::fulfill_redemption_request()`

| Aspect | Detail |
|--------|--------|
| Signers | [the role signer] |
| Access | [role — how enforced: `has_one = redemption_admin` / in-body `require_keys_eq!`] |
| Parameters | [param (role-provided), param (protocol-derived)] |
| Accounts (key) | [...] |
| CPI chain | `→ …` |
| State modified | [...] |
| Value flow | [direction] |

[Repeat per role and instruction. Note two-step authority transfers (propose/accept) — the accept is
role-gated by an in-body check on the proposed key, not a modifier.]

---

## Admin-Only

[Instructions restricted to the top authority (boss / upgrade authority / multisig). They configure rather
than operate. Compact table — auditors need the full admin surface at a glance.]

| Program | Instruction | Access (constraint) | Parameters | State Modified |
|---------|-------------|---------------------|------------|----------------|
| [program] | `set_kill_switch()` | `has_one = boss` (+ admin path) | `enable (bool)` | `state.is_killed` |

---

## Query / Read-Only

[Solana has no `view` — these instructions still execute on-chain, emit events, and cost compute, but do
not mutate persistent state (no `mut` accounts written). List them so auditors know they exist; they can
still leak info or be composed.]

| Program | Instruction | Returns | Reads |
|---------|-------------|---------|-------|
| [program] | `get_nav()` | `u64` | [offer pricing vectors, Clock] |

---

## Initialization

[One-time / lifecycle instructions: `init` / `init_if_needed` / `close`. Attackable during deployment.]

| Instruction | Lifecycle | Account | Reinit-guarded? | Notes |
|-------------|-----------|---------|-----------------|-------|
| `initialize()` | init | `state` PDA | n/a (init) | sets boss |
| `…()` | init_if_needed | `user_token_out` ATA | [yes/no] | [reinit risk if writes initial state] |
```

## Rules
- **No overlap with x-ray.md**: no threat analysis, adversary model, invariants, attack surfaces, git
  history, tests, docs. Those are the readiness report.
- **Factual only**: extract from code; do not speculate or suggest mitigations.
- **CPI chains**: trace the full downstream path to a leaf (token CPI, account write, or external program
  call). Use `→`. Name the concrete program a CPI targets (SPL Token / Token-2022 / Pyth / a PDA-signed
  self-CPI), not a trait.
- **Parameter trust**: `(user-controlled)` = caller chooses freely; `(user-signed)` = from the caller's
  signature; `(approver-signed)` = from an off-chain approver signature verified on-chain (ed25519 via
  instructions sysvar); `(keeper-provided)`; `(protocol-derived)` = read from account state.
- **Access from the Accounts struct**: read `Signer` (who signs), `has_one`/`constraint`/`address=`/
  `#[access_control]` (role/admin), plus in-body `require_keys_eq!`/`require!` (role-without-modifier).
- **Exclude**: pure helper functions not in the `#[program]` module, trait methods, library internals,
  and (for native programs) anything not reachable from the instruction dispatcher.

# Invariant Map Template

Write `invariants.md` using this structure. A deep structural reference for invariants only — no threat
analysis, no git history, no test analysis. It answers: "what must always be true, what enforces it, and
what breaks if it doesn't hold." On Solana, "storage" = persistent account fields; "guards" =
`require!`/`require_*!`/`assert!` and **Anchor account `constraint =`**.

```markdown
# Invariant Map

> [Protocol Name] | [N] guards | [N] inferred | [N] not enforced on-chain

---

## 1. Enforced Guards (Reference)

Per-call preconditions. Heading IDs below (`G-N`) are anchor targets from x-ray.md attack surfaces.

[Doc-comment-stated global invariants do NOT belong here — they route to §2/§3/§4 by shape. Both in-body
`require!` and Accounts-struct `constraint =` / `has_one` count as guards.]

#### G-1
`require!(state.is_killed == false, …)` / `constraint = state.is_killed == false` · `take_offer.rs:71` · [why — what trust boundary or invariant it enforces]

[Repeat `#### G-N` for every guard. Two lines: H4 heading with ID only (preserves `#g-1` anchor), then one
body line with three ` · `-separated fields: verbatim predicate in backticks, file:line in backticks,
purpose prose. Include Accounts-struct constraints (`has_one = boss`, `constraint = …`,
`address = sysvar::…`) as guards — they are per-call preconditions enforced by Anchor. Separate guards
with a blank line only.]

---

## 2. Inferred Invariants (Single-Account / Single-Program)

Derived from structural analysis. Each block cites one of five extraction methods in `Derivation`:

- **Δ-pair (delta-pair)** — two account fields changed by equal-and-opposite amounts in one handler (e.g.
  `state.total += x` paired with `position.amount += x`, or SPL `mint_to(mint, n)` paired with a tracked
  supply field), implying `A == Σ B[key]` or `A + B = const`.
- **Guard/constraint lift** — a `require!`/`constraint =` on an account field, promoted from per-call to
  global by checking *every* write site of that field enforces an equivalent guard. If any write site
  lacks it → On-chain=**No** (candidate bug).
- **State-machine edge** — an account field transitioning through discrete values via
  `require!(state == A); state = B` (or enum status), with no reverse path. One-shot latches & lifecycles.
- **Temporal predicate** — a check tied to `Clock::get()?.unix_timestamp`/`.slot`/`.epoch` or a stored
  deadline/duration field.
- **Doc-comment-stated global property** — a developer-asserted invariant in `///`/`//!` (e.g. *"total
  supply never exceeds max_supply"*). Routed here, then confirmed/contradicted by the structural scan.

Categories by shape: `Conservation` · `Bound` · `Ratio` · `StateMachine` · `Temporal`. Definitions at end of §2.

---

#### I-1

`Category` · On-chain: **Yes/No**

> [the global property claim — prose or code — in a blockquote]

**Derivation** — [Δ-pair / guard-lift + write-sites / edge / temporal / doc-comment citation]

**If violated** — [consequence]

---

[Repeat `#### I-N` for every inferred invariant.]

**Categories:**
- **Conservation**: two+ account fields change equal-and-opposite in one handler. `Δ(A)=+x, Δ(B)=-x → A+B=const`.
- **Bound**: a guard/constraint on a field lifted to a global property and enforced across every write
  site. `require!(fee <= 10_000)` at every writer → `fee ∈ [0,10_000]`. On-chain=**No** if any writer lacks it.
- **Ratio**: a field defined as a formula of other fields. `token_out = token_in * price / scale`.
- **StateMachine**: a field transitions through discrete values with guards preventing reversal.
- **Temporal**: a condition depends on `Clock` (timestamp/slot/epoch) or a stored duration/deadline.

**Doc-comment-routed blocks**: cite as `DocComment: file.rs:LN — "<verbatim>"` in Derivation; still run
the structural scan to set On-chain=Yes/No.

---

## 3. Inferred Invariants (Cross-Program / Cross-Account)

Trust assumptions spanning a CPI boundary or two accounts. Each block cites both sides.

---

#### X-1

On-chain: **Yes/No**

> [what the caller assumes about the CPI callee's effect, a sysvar, or another account's field]

**Caller side** — `Caller.rs:LN` — [how the value/result is used]

**Callee/other side** — `Callee.rs:LN` or [external program / sysvar] — [write site / behavior that could break it]

**If violated** — [consequence]

[Include: token-balance assumptions across a transfer CPI (esp. Token-2022 fee — net received vs requested);
oracle freshness/confidence assumptions; sysvar-derived assumptions; setter-vs-invariant mismatches (an
admin setter writing a field without re-checking an invariant enforced elsewhere). Only blocks where BOTH
sides are in scope — do not speculate about out-of-scope program internals beyond their documented interface.]

---

## 4. Economic Invariants

Higher-order properties derived from §2 + §3. Every block traces to concrete IDs.

---

#### E-1

On-chain: **Yes/No**

> [economic property — e.g. "ONyc circulating ≤ collateral value at NAV"]

**Follows from** — `I-N` + `I-M` [+ `X-N`]

**If violated** — [consequence]
```

## Rules for `invariants.md`
- **Heading-block format, NOT tables**: each is a `#### G-N`/`#### I-N`/`#### X-N`/`#### E-N` heading
  producing a slug anchor (`#g-1`, `#i-17`) that cross-file links in x-ray.md resolve. Never use tables for
  referenced IDs (inline `<a id>` in table cells doesn't work cross-file in VS Code).
- **§1 (Enforced Guards) is reference-only**: each `G-N` is the H4 heading then one body line with three
  ` · `-separated fields (verbatim predicate, `file:line`, purpose). Purpose MUST explain *why*, not
  restate the check. Anchor `constraint =`/`has_one`/`address =` are guards.
- **Guard/constraint that implies a global property** → §2 as a Bound `I-N` via the lift methodology
  (SKILL.md Step 2g).
- **Doc-comment routing**: developer-stated global invariants route DIRECTLY to §2/§3/§4 by shape, never §1.
- **Derivation discipline**: every inferred block cites exactly one of: `Δ-pair: file:Lx ↔ file:Ly`;
  `guard-lift: <verbatim require!/constraint> + <write-site enumeration>`; `edge: State@Lx → State@Ly`;
  `temporal: <verbatim Clock/deadline check>`; `DocComment: file:LN — "<verbatim>"`. No "implied by semantics."
- **On-chain field**: Yes or No only. If partial, split into two blocks. Guard-lift with any unguarded
  write site is On-chain=No.
- **Cross blocks (§3)**: cite both sides; both in scope (a CPI callee may be cited by its documented
  interface — e.g. SPL transfer semantics — but flag the assumption explicitly).
- **No fabrication**: untraceable invariant → omit. Anchor slug links use LOWERCASE (`invariants.md#x-4`).

# Architecture Diagram Guide

## architecture.json Format

```json
{
  "title": "[Protocol] Architecture",
  "nodes": [
    {"id": "unique_id", "label": "DisplayName", "subtitle": "One-word role", "type": "actor|protocol|external", "row": 0}
  ],
  "edges": [
    {"from": "source_id", "to": "target_id", "label": "action description"}
  ],
  "groups": [
    {"label": "Group Name", "nodes": ["id1", "id2"]}
  ]
}
```

### Node types (Solana semantics)
- `actor`: users/roles/signers (User, Boss, Admin, Approver, Keeper) — pill shape
- `protocol`: in-scope program(s), key PDAs/accounts, instruction groups — blue accent stripe
- `external`: out-of-scope programs this one CPIs into (SPL Token / Token-2022, Pyth, Switchboard, a DEX,
  a stake pool, System program) — amber accent stripe

### subtitle
Optional short role (e.g. "Coordinator", "Price Feed", "Vault PDA", "Mint Authority"). For composite nodes,
list individual modules/PDAs (e.g. "offer / redemption / vault").

### row
Assign rows to **minimize edge distance**, not by node type. Actors top, leaf dependencies (token program,
oracle, system program) bottom, core program(s) middle. A CPI target called only from row 1 belongs on row
2 — not a distant "externals" row.

### groups
Optional. Group related nodes (e.g. "Offer Subsystem", "Vault PDAs").

**Group containment rule (CRITICAL):** every node is either inside exactly one group, or on a row with NO
group box. Ungrouped node on a grouped row will visually escape the box — add it to a group or move its row.
Classify by **primary caller** (e.g. a mint-authority PDA called by the program core belongs in the core
group).

---

## Budgets & Layout Rules

### Node & edge budgets
Scale budget by in-scope module/program count (excluding generated code):

| In-scope units | Max nodes | Max edges | Max per row |
|---------------:|----------:|----------:|------------:|
| ≤10 | 12 | 14 | 4 |
| 11–20 | 16 | 18 | 4 |
| 21–35 | 20 | 22 | 5 |
| 36+ | 24 | 26 | 5 |

**Prioritize completeness over compression.** Every PDA that holds funds or signs, every account that gates
access, and every external CPI target on a critical path should be visible — as its own node or named in a
composite subtitle.

### Compositing rules (apply first tier that fits the budget)
- **Tier 1 — Always composite**: same-subsystem modules/instructions with identical caller AND callee. Use
  subsystem label, list in subtitle.
- **Tier 2 — When budget requires**: same primary caller OR callee. Helper PDAs composite into their parent.
- **Tier 3 — Last resort**: same-subsystem, same trust level, different callers/callees.
- **Never composite across trust levels** — combining a permissionless instruction group and an admin-only
  one hides the trust boundary.

### Actor and external rules
- **Combine actors** only when same trust level AND capabilities. Keep boss/admin/user separate.
- **External CPI targets** that are sole data sources for critical logic (Pyth/Switchboard oracle) get their
  own node. Token programs / System program can composite when budget is tight.

### Same-row arc, hub, and edge rules
- ≤2 same-row arcs per node; 3+ → move one target to an adjacent row. Balance 2 arcs LEFT/RIGHT.
- The generator auto-routes a long same-row arc below the row when it would cross boxes (staggered depths).
- Hub (3+ same-row connections): place it **centrally** among its same-row targets in the JSON ordering.
- **Every edge label unique**; 2-3 words max; **no row-skipping edges** (adjacent rows or same row only);
  show primary flows (CPIs, signer authority, token movement), not every internal call.

---

## SVG Generation & Validation

### Generate
```bash
python3 $SKILL_DIR/scripts/generate_svg.py x-ray/architecture.json x-ray/architecture.svg
```

### Render to PNG for inspection (try in order; skip validation if none available)
```bash
convert -density 300 x-ray/architecture.svg /tmp/architecture-preview.png
rsvg-convert x-ray/architecture.svg -o /tmp/architecture-preview.png
python3 -c "import cairosvg; cairosvg.svg2png(url='x-ray/architecture.svg', write_to='/tmp/architecture-preview.png', scale=3)"
```
Then `Read` the PNG.

### Audit checklist (max 3 iterations)
1. **Structure**: top-to-bottom flow? Actors top, external programs (token/oracle/system) bottom, core middle?
2. **Edge labels**: readable (≥4.5), dark (#1E293B), sitting on arrows.
3. **Edge routing**: no row-skipping, no arrows through boxes; same-row arcs balanced; long crossing arcs route below.
4. **No overlapping labels**: stagger y by ≥8 if boxes overlap.
5. **Groups**: aligned rects; no ungrouped node on a grouped row.
6. **Centering**: balanced across rows.

### Fix types
- **JSON-level** (regenerate): rows, ordering, edges, groups → edit JSON, re-run, re-render.
- **SVG-level** (post-process): label font/color/position → edit SVG directly, re-render.

### Cleanup
```bash
rm -f x-ray/architecture.json x-ray/git-security-analysis.json /tmp/architecture-preview.png
```
