# Solana / Anchor Vulnerability Class Library

> **HOW TO USE THIS FILE**
>
> This is the Solana/Anchor analog of the EVM "common vulnerabilities" knowledge an auditor carries in
> their head. Solana's account model produces an entirely different bug surface than the EVM: there is no
> implicit `msg.sender`, no automatic storage ownership, no contract-type safety at the call boundary.
> **Every account a program touches is attacker-supplied until proven otherwise.**
>
> - **In Step 2d-sol (Account-Validation Scan)** — walk this checklist for each instruction handler and
>   its `#[derive(Accounts)]` struct. Flag the classes whose detection signals are present AND whose
>   mitigating constraint is absent.
> - **In Step 3a (Key Attack Surfaces)** — frame surfaces around the *class* (e.g. "unconstrained CPI
>   target program"), not the individual exploit. Obey the DO-NOT-EXPLOIT rule from `templates.md`.
>
> **Anchor mitigates many of these by default** via typed accounts (`Account<'info, T>` checks owner +
> discriminator; `Signer` checks the signature; `Program`/`Sysvar` check the address). The risk re-opens
> wherever the code drops to raw `AccountInfo` / `UncheckedAccount` / `/// CHECK:` or does manual
> deserialization. The single highest-signal grep on any Anchor codebase is therefore the set of
> `UncheckedAccount` / `AccountInfo` / `CHECK:` sites — each is a place the developer turned the
> guardrails off and took responsibility for validation manually.

---

## 1. Missing signer check

**Why (Solana-specific):** There is no `msg.sender`. Authorization is proven only by an account being a
transaction signer. A handler that reads `authority.key()` but never requires `authority` to sign lets
anyone pass any pubkey as the "authority".

**Detection signals:** an account used for authorization that is typed `AccountInfo`/`UncheckedAccount`
(not `Signer`); absence of `Signer<'info>` on the privileged actor; manual flows that compare a key but
never check `.is_signer`.

**What to look for:** for every privileged action, is the authority a `Signer`? If it's a stored role
(`state.boss`), is the *signer* checked equal to it (`has_one`, `require_keys_eq!`, or `constraint`)?
A `has_one = boss` with no `Signer` for boss only proves the account *matches* — it does not prove the
boss *authorized* anything.

**Anchor mitigation:** `Signer<'info>` enforces the signature. Gap re-opens with `AccountInfo` +
manual `is_signer` (or no check).

---

## 2. Missing owner / account-type check (account substitution, "type cosplay")

**Why:** Any account can be passed where any account is expected. If the program deserializes an account
without checking (a) the owning program and (b) the account discriminator/type, an attacker can substitute
a different account they control with attacker-chosen bytes — or one type's account where another is
expected (two Anchor accounts with the same layout are interchangeable if discriminators aren't checked).

**Detection signals:** manual `try_from_slice` / `try_deserialize` on `AccountInfo` data; `UncheckedAccount`
read as state; missing `owner = ` / typed-account usage; same-size structs without distinct discriminators.

**What to look for:** is every state account a typed `Account<'info, T>` (owner + discriminator checked) or
a `zero_copy` `AccountLoader<'info, T>`? Where raw data is parsed, is `account.owner == program_id`
asserted and the discriminator validated? Could account X of type A be passed where type B is expected?

**Anchor mitigation:** `Account<T>` / `InterfaceAccount<T>` / `AccountLoader<T>` check owner +
discriminator automatically. Gap re-opens with raw `AccountInfo` + manual deserialize.

---

## 3. PDA seed & canonical-bump issues, seed collisions

**Why:** PDAs are the program's authority and storage namespace. Two failure modes: (a) using a
non-canonical bump (`create_program_address` with an attacker-supplied bump instead of the canonical one
from `find_program_address`) lets multiple valid addresses exist for "the same" logical account;
(b) **seed collision** — if two distinct logical accounts can derive to the same seeds (e.g. user-supplied
strings concatenated without a separator), one can be substituted for the other.

**Detection signals:** `create_program_address`, `Pubkey::create_program_address`, a `bump` taken from
instruction data instead of `ctx.bumps`, `seeds = [...]` containing unbounded user input, string
concatenation in seeds.

**What to look for:** does every PDA use the canonical bump (`bump` in the Accounts constraint, or
`ctx.bumps.x`)? Are seeds collision-free (fixed prefixes, length-delimited, or fixed-width keys)? Is a
stored bump validated against the canonical one? Are signer seeds for `invoke_signed` exactly the
account's own seeds?

**Anchor mitigation:** `#[account(seeds = [...], bump)]` enforces the canonical bump on validation;
`#[account(seeds=[...], bump = stored.bump)]` validates a stored bump. Gap re-opens with manual PDA
derivation.

---

## 4. Arbitrary CPI / unconstrained program account

**Why:** A cross-program invocation calls whatever program account is passed in. If the "token program"
(or any callee) is an unchecked `AccountInfo`, an attacker passes their own program that mimics the
interface, intercepts the call, and (e.g.) reports a transfer succeeded without moving funds.

**Detection signals:** `invoke` / `invoke_signed` to a program taken from `AccountInfo`/`UncheckedAccount`;
a `token_program` / callee not typed `Program<'info, Token>` or `Interface<'info, TokenInterface>`; missing
`address = ` / program-id constraint on the callee.

**What to look for:** is every CPI target program id constrained — typed `Program<T>`, `Interface<T>`, or
an explicit `address = expected::id()` / `require_keys_eq!`? For token CPIs, is the token program pinned
to the real SPL Token / Token-2022 id (and does the mint's owner match the token program used)?

**Anchor mitigation:** `Program<'info, Token>` / `Interface<'info, TokenInterface>` pin the program id.
Gap re-opens with `AccountInfo` CPI targets.

---

## 5. Account close → revival / zombie accounts

**Why:** "Closing" an account = draining its lamports below rent-exemption so the runtime garbage-collects
it *after* the transaction. If you only refund lamports but don't zero the data and set the closed
discriminator, an attacker can top the account back up (or re-use it within the same/next tx) with stale
data still present — a revival attack. Manual close is error-prone.

**Detection signals:** manual lamport draining (`**dest.lamports.borrow_mut() += ...; **acc.lamports... = 0`)
without zeroing data; absence of the `close = ` Anchor constraint; `realloc` without zero-init; re-`init`
of a previously used PDA.

**What to look for:** are closed accounts closed via Anchor's `#[account(close = recipient)]` (which zeroes
data + writes the CLOSED discriminator)? If manual: is data zeroed AND the discriminator invalidated AND
lamports drained? Can the account be re-initialized or revived?

**Anchor mitigation:** `close = recipient` does it safely. Gap re-opens with manual close logic.

---

## 6. Duplicate mutable accounts

**Why:** Anchor does not, by default, check that two account fields are *different* accounts. If a handler
takes `from` and `to` and applies `from -= x; to += x`, passing the same account for both can net-zero a
debit, or double an effect, depending on in-memory aliasing.

**Detection signals:** two+ mutable accounts of the same type in one Accounts struct; arithmetic that moves
value between two same-type accounts; no `constraint = a.key() != b.key()`.

**What to look for:** for any handler that mutates two accounts of the same type, is there a
`constraint = x.key() != y.key()` (or Anchor's `#[instruction]`/explicit check)? Reason about the same
account being supplied twice.

**Anchor mitigation:** none automatic — must be an explicit `constraint`.

---

## 7. `init_if_needed` reinitialization

**Why:** `init_if_needed` creates the account if absent, else uses the existing one. If the handler then
*unconditionally* writes initial state (owner, authority, config), an attacker can call it again on an
already-initialized account to reset critical fields — a reinitialization attack.

**Detection signals:** the `init_if_needed` Anchor feature enabled (Cargo `features = ["init-if-needed"]`)
and used; initial-state assignment that runs every call rather than only on first init.

**What to look for:** every `init_if_needed` site — is there a guard preventing re-initialization of an
already-populated account (e.g. `require!(account.authority == default)` or only writing when freshly
created)? Could a second call overwrite authority/config?

**Anchor mitigation:** `init` (not `init_if_needed`) fails if the account exists. `init_if_needed`
requires manual reinit protection.

---

## 8. Stale account data after CPI (missing reload)

**Why:** After a CPI mutates an account (e.g. a token transfer changes a token account's balance), the
in-memory deserialized copy in the caller is **not** automatically refreshed. Reading `.amount` after the
CPI without `.reload()` uses the pre-CPI value — leading to wrong accounting.

**Detection signals:** a balance/amount read after a `token::transfer`/`mint_to`/`burn` CPI without an
intervening `.reload()`; computing deltas across a CPI.

**What to look for:** anywhere the code reads a token/account field *after* a CPI that changed it — is
`.reload()` called? Are balance-delta checks computed from reloaded values?

**Anchor mitigation:** none automatic — must call `.reload()`.

---

## 9. Sysvar / well-known-account spoofing

**Why:** Sysvars (Clock, Rent, Instructions) and well-known programs are just accounts. If passed as raw
`AccountInfo` and read without an address check, an attacker supplies a fake sysvar with chosen values
(e.g. a forged Clock, or a forged Instructions sysvar to bypass instruction-introspection checks used for
ed25519/secp256k1 signature verification).

**Detection signals:** `Instructions` sysvar / `Clock` / `Rent` as `AccountInfo` without
`address = sysvar::...::id()`; `load_instruction_at_checked` on an unverified instructions account.

**What to look for:** are sysvars typed `Sysvar<'info, Clock>` or constrained with
`address = sysvar::instructions::id()`? For ed25519/secp256k1 verification done via instruction
introspection, is the instructions sysvar address validated AND the introspected instruction's program id,
data, and accounts checked? (onre-sol does this correctly: `#[account(address = sysvar::instructions::id())]`.)

**Anchor mitigation:** `Sysvar<T>` and `address =` enforce identity. Gap re-opens with raw `AccountInfo`.

---

## 10. Integer overflow / unchecked arithmetic

**Why:** **Rust in release mode wraps on overflow** (no panic) unless `overflow-checks = true` is set.
Solana programs ship in release. So `a + b`, `a * b`, `a - b` can silently wrap — under/overflowing
balances, share math, or fees. This is one of the most common real Solana bugs.

**Detection signals:** raw `+ - *` on `u64`/`u128` token/amount math; absence of
`checked_add`/`checked_mul`/`checked_sub`/`saturating_*`; `overflow-checks` not set to `true` in any
`Cargo.toml` profile (enumerate reports this as `overflow_checks`).

**What to look for:** is `overflow-checks = true` set for the release profile? In hot math (pricing,
shares, fees, interest), is checked/saturating arithmetic used and are the error paths correct? Watch
subtraction that could underflow (`balance - amount` without a `>=` guard). (onre-sol sets
`overflow-checks` and uses a `MathOverflow` error — good signal.)

**Anchor mitigation:** none — purely a coding/profile discipline. `overflow-checks = true` is the
backstop; checked math is the belt.

---

## 11. `remaining_accounts` handling

**Why:** `ctx.remaining_accounts` is a raw, unvalidated, variable-length list of `AccountInfo`. Anchor
applies **no** constraints to them. Programs that iterate them (multi-hop routers, batch ops) must validate
each: owner, type, signer, ordering, and that the caller can't inject extra or substitute accounts.

**Detection signals:** `ctx.remaining_accounts`, `remaining_accounts.iter()`, indexing into remaining
accounts.

**What to look for:** every use of `remaining_accounts` — is each element validated (owner/type/key)? Is
the count and order enforced? Can an attacker add a rogue account to the list?

**Anchor mitigation:** none — fully manual.

---

## 12. SPL Token / Token-2022 assumptions

**Why:** Token accounts and mints are passed in. Common bugs: not checking a token account's `mint`
matches the expected mint; not checking its `owner`/`authority`; assuming a fixed `decimals`; and, with
**Token-2022**, ignoring extensions — **transfer-fee** (received amount < sent amount, the Solana analog
of fee-on-transfer), **transfer-hook** (arbitrary CPI on transfer → reentrancy/again-arbitrary-program),
**freeze authority** (funds can be frozen), **confidential transfer**, **permanent delegate**, and
**default-account-state**.

**Detection signals:** `Token-2022` / `spl-token-2022` / `token_interface` / `TokenInterface` usage;
`transfer` vs `transfer_checked`; reads of `.amount` without before/after delta; hardcoded decimals;
ATA constraints (`associated_token::mint/authority`).

**What to look for:** does each token account constrain `mint` and `authority`? Is `transfer_checked`
(mint + decimals verified) used over `transfer`? For Token-2022, are transfer fees accounted for with a
balance-delta (`before`/`after` + `reload`)? Are transfer-hook programs expected/validated? Is freeze /
permanent-delegate risk acknowledged? (onre-sol supports Token-2022 transfer-fee mints — verify the
deposit/withdraw/take paths use net-received amounts.)

**Anchor mitigation:** `InterfaceAccount<'info, TokenAccount>`/`Mint` + `associated_token::*` constraints
check mint/authority/program. Extension semantics (fees/hooks) are still the program's responsibility.

---

## 13. Rounding / precision direction

**Why:** Share/price/fee math with integer division must round in the protocol's favor. Rounding the wrong
way (or inconsistently between deposit and withdraw) lets an attacker extract value over many round-trips —
the Solana version of the ERC4626 share-rounding bug. First-depositor/empty-state share inflation applies
to vault-like programs.

**Detection signals:** integer `/` in share/price/fee math; `checked_div`; conversions between token
amounts and shares; first-deposit / `total_supply == 0` branches.

**What to look for:** does each division round in the protocol's favor (and consistently across the
inverse operation)? Is there a first-depositor / empty-vault guard (minimum deposit, virtual shares)? Are
mantissa/scale conversions (e.g. onre-sol's `dec9`, PRICE_DECIMALS=9) lossless or biased safely?

**Anchor mitigation:** none — math discipline.

---

## 14. Unvalidated instruction data / deserialization

**Why:** Instruction args and any Borsh-deserialized blobs are attacker-controlled. Missing bounds checks
(array indices, vector lengths, fee basis points, durations) lead to panics (DoS) or logic errors.

**Detection signals:** indexing with a user-supplied index; `Vec` growth from user input; unbounded
loops over user data; basis-point / percentage params without range checks.

**What to look for:** are numeric params range-checked (fees ≤ 10_000 bps, durations bounded, indices <
len)? Are vector lengths capped (onre-sol caps MAX_VECTORS/MAX_ADMINS)? Could a param force a panic or
unbounded compute?

**Anchor mitigation:** none — explicit `require!`/`constraint` validation.

---

## 15. Lamport / rent manipulation & account-size griefing

**Why:** Direct lamport math, `realloc`, and rent assumptions are manual. Bugs: reading
`account.lamports()` as protocol balance (anyone can send lamports to any account — a donation that skews
accounting), `realloc` without zeroing new bytes, or not accounting for rent on close/refund.

**Detection signals:** `lamports()` read as a balance, `try_borrow_mut_lamports`, `realloc(`,
`AccountInfo::realloc`.

**What to look for:** is on-chain "balance" tracked in program state, not inferred from
`account.lamports()`? Does `realloc` zero-initialize? Are rent/refund flows correct on close?

**Anchor mitigation:** `#[account(realloc = ..., realloc::zero = true)]` handles realloc zeroing; lamport
accounting is otherwise manual.

---

## Quick Scan Checklist (apply per handler in Step 2d-sol)

For each instruction handler + its `#[derive(Accounts)]` struct, confirm:

1. **Signer** — privileged action gated by a `Signer` that is checked equal to the stored role.
2. **Owner/type** — every state account typed (`Account<T>`/`AccountLoader<T>`), not raw `AccountInfo`.
3. **PDA** — canonical `bump`; collision-free `seeds`; `invoke_signed` seeds are the account's own.
4. **CPI target** — callee programs pinned (`Program<T>`/`Interface<T>`/`address =`).
5. **Close/realloc** — `close =` used; no manual revival path; `realloc` zeroes.
6. **Duplicates** — same-type mutable accounts have a `key() != key()` constraint.
7. **init_if_needed** — reinit-guarded.
8. **Reload** — account fields re-read after a mutating CPI.
9. **Sysvars** — typed/`address =` constrained (esp. instructions sysvar for sig checks).
10. **Math** — `overflow-checks = true` and/or checked/saturating arithmetic in value math.
11. **remaining_accounts** — each validated.
12. **Token** — mint/authority constrained; `transfer_checked`; Token-2022 fee/hook handled.
13. **Rounding** — divisions favor the protocol; first-deposit guarded.
14. **Input** — numeric params range-checked; vectors bounded.

Every `UncheckedAccount` / `AccountInfo` / `/// CHECK:` site is where one or more of the above was made the
developer's manual responsibility — start there.
