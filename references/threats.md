# Protocol-Type Threat Profiles (Solana / Anchor)

> **HOW TO USE THIS FILE**
>
> Treat this file as a threat *identification* library, **not** as a prose template for the final report.
>
> - **In Step 2e (Protocol Classification)** — use the detection-signals table to label the protocol by type.
> - **In Step 3a (Writing Section 2 of x-ray.md)** — use adversary rankings, attack patterns, and critical
>   invariants here to know *what to look for* and *who threatens the protocol*, then TRANSLATE that into
>   the output format.
>
> **DO NOT copy exploit-chain prose verbatim into Key Attack Surfaces.** Phrases like *"manipulate the
> oracle → mint against fake collateral → drain the vault"* are intentional here — they teach the threat —
> but the `templates.md` **DO-NOT-EXPLOIT RULE** forbids them in the report. Convert "→ attacker drains X"
> into "worth tracing…" / "worth checking…". Name the surface and the concern; let the auditor finish it.
>
> For the account-model bug classes (signer/owner/PDA/CPI/close/overflow) that cut across ALL protocol
> types, use `solana-vulns.md` — this file covers protocol-economic threats by type.

This reference provides per-protocol-type threat intelligence. The skill auto-classifies the protocol from
code signals in Step 2, then uses the matching profile(s) to weight adversaries, attack patterns, and
surfaces. Detection signals are Rust/Anchor function and type names.

## Protocol Classification Signals

A protocol may match **multiple types** (hybrid). Rank by signal density — the type with the most matches
is primary. Solana protocols are frequently custom hybrids (e.g. RWA / NAV-priced redemption like onre-sol
= Stablecoin + Vault characteristics).

| Type | Detection Signals in Code |
|------|--------------------------|
| **Lending/Borrowing** | `borrow`, `repay`, `liquidate`, `health_factor`/`health`, `collateral`, `ltv`, `debt`, `interest`/`borrow_rate`, reserve/obligation accounts. Solana exemplars: Solend, MarginFi, Kamino Lend. |
| **DEX/AMM** | `swap`, `add_liquidity`/`deposit_liquidity`, `remove_liquidity`, constant-product (`x*y=k`), `sqrt_price`/`tick` (concentrated), LP mint, `amount_out`, reserves, orderbook (`bid`/`ask`/`fill`). Exemplars: Raydium, Orca Whirlpools, Meteora, Phoenix, OpenBook. |
| **Vault / Yield** | `deposit`/`withdraw` + `shares`/`total_assets`/`total_shares`, strategy + `harvest`/`rebalance`, share-price/exchange-rate. Exemplars: Kamino, Meteora vaults, Tulip, Francium. |
| **Stablecoin / RWA** | mint/burn against collateral, `nav`/`peg`/`target`, `collateral_ratio`, redemption at price, `max_supply` cap, PSM-like swap. Exemplars: onre-sol (RWA), Parcl, custom CDPs. |
| **Derivatives/Perps** | `open_position`/`close_position`, `funding_rate`, `margin`, `leverage`, `pnl`, `mark_price`/`index_price`, position account with size/collateral/entry. Exemplars: Drift, Mango, Zeta, Jupiter Perps. |
| **Liquid Staking** | `stake` + derivative mint, `unstake`/`deposit_stake`, exchange rate, validator/stake-pool management, withdrawal ticket/queue. Exemplars: Marinade (mSOL), Jito (JitoSOL), Sanctum, BlazeStake, SPL Stake Pool. |
| **Bridge / Messaging** | cross-chain message, `lock`/`unlock` or `burn`/`mint`, guardian/relayer/oracle set, VAA/message nonce, chain id, merkle/signature proof. Exemplars: Wormhole, deBridge, Allbridge, Portal, LayerZero. |
| **Governance / Multisig** | `propose`, `vote`, `execute`, `queue`, quorum, voting-power snapshot, delegation, threshold, transaction account. Exemplars: SPL Governance / Realms, Squads, Mythic/Goki. |

### Hybrid Classification
1. Rank by signal count — more matches = higher weight.
2. **Primary type** sets adversary ranking order.
3. **Secondary types** add their unique threats (de-duplicate overlaps).
4. Output: "Protocol classified as: **[Primary]** with **[Secondary]** characteristics".

---

## Threat Profiles by Protocol Type

> Each profile lists the *protocol-economic* adversaries and patterns. The account-model checklist in
> `solana-vulns.md` applies on top of every type.

### Lending / Borrowing

**Primary adversaries (ranked):**
1. **Oracle manipulator** — Pyth/Switchboard price (or a derived AMM price) drives solvency. Manipulating
   it, or exploiting staleness/confidence, makes collateral look over-valued or debt under-valued.
2. **Liquidation MEV searcher / Jito bundler** — extracts value from liquidations; on Solana, Jito bundles
   and leader-slot ordering replace mempool front-running but achieve similar effects.
3. **First-depositor / share manipulator** — share-based supply/debt accounting is inflatable on empty
   reserves (the SPL analog of the ERC4626 inflation attack).
4. **Compromised admin / upgrade authority** — can change collateral factors, oracle accounts, interest
   models, or pause/redeploy the program.

**Dominant attack patterns:** oracle manipulation → inflated collateral → max borrow → drain reserve;
stale Pyth price (no `get_price_no_older_than` / confidence check) → borrow at wrong price; bad-debt
accumulation when liquidation is unprofitable; reserve-utilization games to move rates.

**Critical invariants:** `total_borrows ≤ Σ collateral · LTV`; every unhealthy position is liquidatable
before bad debt; oracle price fresh + within confidence; interest accrual monotonic.

**Look first:** the full price path (oracle account → staleness/confidence checks → collateral value →
health); can one tx borrow+manipulate+liquidate (flash-loan-like via Solana flash loans / Jito)?;
share math at `total == 0`; what the upgrade authority/admin can change instantly.

---

### DEX / AMM

**Primary adversaries:**
1. **MEV / sandwich searcher (Jito)** — sandwich swaps via bundle ordering; every swap without slippage
   protection is extractable.
2. **Flash-loan / same-tx price manipulator** — moves pool price within a tx (Solana flash loans, or
   atomic multi-ix).
3. **First-LP / empty-pool attacker** — sets initial price/tick or inflates LP-share price via donation.
4. **Compromised admin** — fee/routing/pool-whitelist control.

**Dominant attack patterns:** sandwiching; LP-share inflation on new pools (direct token donation to the
vault ATA inflates share price — does `total_assets` read the ATA balance or internal accounting?);
reentrancy via **Token-2022 transfer hooks** during swaps; spot price read by *other* programs as an
oracle → manipulate-in-same-tx; tick-boundary manipulation; fee-on-transfer (Token-2022) accounting.

**Critical invariants:** pool invariant holds across every op; reserves in state == actual ATA balances
(no donation surface); swap output matches curve math exactly (rounding favors pool); LP value
monotonic from fees.

**Look first:** swap math + rounding direction; LP mint/burn at `total_supply==0` + min-liquidity; does
the pool expose a price other programs consume?; slippage enforcement; **transfer-hook reentrancy**.

---

### Vault / Yield

**Primary adversaries:**
1. **Share-inflation first depositor** — deposit 1, donate a large amount to the vault ATA to inflate
   `total_assets` without minting shares, next depositor rounds to 0 shares.
2. **Malicious/compromised strategy** — strategies hold the funds; can report fake P&L or retain ATA
   delegation/approval after migration.
3. **Donation/direct-transfer attacker** — anyone can transfer tokens to the vault ATA; if `total_assets`
   reads `ata.amount`, share price moves.
4. **Compromised admin** — adds malicious strategy, changes allocation/harvester.

**Dominant attack patterns:** share inflation; harvest sandwich; strategy reports fake gain → deposit at
inflated price; accounting desync when underlying rebases or accrues outside the vault's view.

**Critical invariants:** `total_assets` reflects real underlying; round-trip `to_shares∘to_assets ≤ id`;
strategy can't extract more than allocated; share price rises only from yield.

**Look first:** `to_shares`/`to_assets` rounding + virtual-offset/min-deposit; does `total_assets` use ATA
balance or internal accounting?; strategy interface powers; reentrancy via CPI to external protocols;
migration drops old delegation.

---

### Stablecoin / RWA

**Primary adversaries:**
1. **Oracle / NAV manipulator** — manipulating collateral price or the NAV feed mints against fake value
   or forces unfair redemption.
2. **Economic / governance attacker** — changes collateral params, ratios, or fees to extract value.
3. **Bank-run / redemption attacker** — drains the best/liquid collateral first under stress.
4. **Compromised admin / mint authority** — controls collateral set, oracle accounts, debt ceiling,
   redemption pause, **mint authority** (can mint unbacked supply).

**Dominant attack patterns:** collateral/NAV manipulation → mint → sell → undercollateralized; redemption
DoS draining liquid collateral; mint-authority abuse; stale-price mint/redeem arbitrage; fee/round-trip
loops that net value.

**Critical invariants:** every unit backed ≥ ratio; mint and redeem are inverse (no profitable loop);
`total_supply ≤ max_supply`/debt ceiling; mint authority strictly controlled (program PDA vs admin key).

**Look first:** mint path (who holds mint authority — program PDA or boss key?, what bounds it,
`max_supply` cap); redemption pricing/queue under stress; fee round-trips; what the upgrade authority can
change. (onre-sol: NAV-priced ONyc mint/redeem against USDC, `max_supply` cap, boss/redemption_admin —
trace mint-authority transfer and redemption fulfillment.)

---

### Derivatives / Perps

**Primary adversaries:** oracle manipulator (leverage amplifies oracle error); liquidation MEV searcher;
funding-rate manipulator (skew open interest); position-size attacker (exceed payout capacity);
compromised admin (leverage/funding/oracle params, pause).

**Dominant attack patterns:** oracle manipulation → cascade liquidation; funding manipulation via one-sided
OI; positions exceeding pool payout; stale-oracle directional bet; ADL manipulation.

**Critical invariants:** Σ PnL = 0 (minus fees); available liquidity ≥ worst-case payout; liquidation
triggers before bad debt; funding converges OI; mark within bounds of index.

**Look first:** PnL math across sign/leverage limits; liquidation trigger vs insolvency margin; mark vs
index derivation + manipulability in a slot; OI/position caps; funding bounds.

---

### Liquid Staking

**Primary adversaries:** exchange-rate manipulator (mSOL/SOL-style rate via rewards/slashing reporting or
donation); validator/stake-pool attacker; withdrawal-queue griefer; rate arbitrageur (stale rate vs real);
compromised admin (validator set, fees, withdrawal mechanism).

**Dominant attack patterns:** rewards/slashing reporting manipulation; withdrawal-ticket griefing;
integrators mishandling the rate; donation to the pool inflating rate; epoch-boundary timing.

**Critical invariants:** exchange rate reflects true staked + rewards − slashing; `derivative_supply ·
rate ≤ underlying`; withdrawal queue fair; slashing reflected before exit at stale rate.

**Look first:** rate calculation + who/when updates it; withdrawal mechanism (ticket/queue/delay/grief);
validator/stake-pool selection authority; donation surface to the pool.

---

### Bridge / Messaging

**Primary adversaries:** guardian/relayer/oracle-set attacker (#1 bridge loss vector); message-replay
attacker; finality/reorg exploiter; fake-message crafter (proof/VAA verification edge cases); compromised
admin/upgrade authority (highest-value key in the system).

**Dominant attack patterns:** signer-set compromise → forge messages → mint unbacked; replay (missing/weak
nonce or consumed-flag); proof/signature verification bypass; chain-id confusion; reorg between source
finality and destination mint.

**Critical invariants:** locked == minted (1:1); every message processed exactly once; message
unforgeable without threshold; cross-chain accounting consistent.

**Look first:** guardian/relayer trust model + threshold + rotation; replay protection (nonce/consumed
account); proof/signature verification (ed25519/secp256k1 via instructions sysvar — see `solana-vulns.md`
§9); finality assumptions; upgrade-authority blast radius.

---

### Governance / Multisig

**Primary adversaries:** flash-borrow voter (if voting power = current balance, not a snapshot); slow
governance-capture; proposal-spam/obfuscation attacker; timelock-exploitation attacker; compromised
guardian (emergency bypass). For multisig (Squads-style): threshold compromise, member-set manipulation,
stale/duplicate transaction-account execution.

**Dominant attack patterns:** flash vote (no snapshot); hidden malicious instruction in a benign-looking
proposal/transaction account; timelock front-run; member/threshold change abuse; re-execution of an
already-executed transaction account.

**Critical invariants:** voting power snapshotted at proposal creation; quorum/threshold prevents minority
capture; timelock gives exit time; no single role bypasses governance; executed transactions can't replay.

**Look first:** voting-power source (snapshot vs live token balance); quorum/threshold + token/member
distribution; timelock delay; what governance controls; emergency/guardian powers; transaction-account
execution-once enforcement.

---

# Temporal Threat Dimension

Solana programs have a lifecycle; different threats dominate at different phases. Detect which phases are
relevant from code signals and include the applicable ones in the threat model.

| Phase | Include When |
|-------|-------------|
| **Deployment & Initialization** | Always — every program has this. |
| **Steady State** | Always — baseline (covered by protocol-type + account-model libraries). |
| **Market Stress** | Oracle/price dependence, liquidation logic, or collateral/debt tracking exists. |
| **Governance & Upgrade Windows** | Upgradeable program (BPF Upgradeable Loader / non-frozen authority), governance/multisig, or timelock exists. |
| **Deprecation & Wind-down** | V2/migration in names/comments, `migrate`, multi-version, or deprecated accounts. |

## Phase 1: Deployment & Initialization
The most dangerous window — program goes live with real value. Threats:
- **Initialization front-running / hijack** — `initialize` callable by anyone sets boss/authority/config;
  an attacker front-runs (or re-runs `init_if_needed`) to seize control. Look for `initialize` without a
  signer/authority binding, or `init_if_needed` without reinit guard (see `solana-vulns.md` §1, §7).
- **PDA pre-creation / squatting** — a global PDA (config/state) creatable by anyone before the team does.
- **Parameter misconfiguration** — test values live (zero delays, placeholder oracle accounts, fee=0 or
  max, upgrade authority still a dev EOA, mint authority not yet moved to the program PDA).
- **Authority not transferred** — deployer keypair still holds upgrade/mint/admin authority; intended
  move to a Squads multisig hasn't happened.
- **Empty-state exploitation** — first depositor / first LP sets share price or initial ratio.

## Phase 2: Steady State
Covered by the protocol-type profiles above and `solana-vulns.md`. Skip in the temporal section to avoid
duplication.

## Phase 3: Market Stress
- **Oracle staleness/confidence under volatility** — Pyth/Switchboard heartbeat means stale prices during
  fast moves; is `get_price_no_older_than` + confidence-interval checking used? What on a zero/negative/
  stale price?
- **Liquidation cascade** — on-market collateral dumps move price → more liquidations; circuit breaker?
- **Liquidity evaporation** — liquidations unprofitable when AMM liquidity thins; Jito-only liquidators?
- **Correlated depeg** — assumes USDC=$1, mSOL=SOL, etc.; hardcoded 1:1 equivalences.
- **Compute-unit / congestion** — keeper/liquidation ixs fail under CU limits or congestion; priority-fee
  assumptions; time-windowed ops that can miss their window.

## Phase 4: Governance & Upgrade Windows
- **Program upgrade authority** — BPF Upgradeable Loader: who holds upgrade authority? Multisig/timelock,
  a dev key, or is it frozen (immutable)? An upgrade can change *any* logic, including draining vaults or
  altering storage layout. Highest-leverage centralization surface.
- **Storage-layout migration** — a new program version reinterpreting existing account bytes (no
  discriminator/version bump) corrupts state.
- **Timelock exploitation** — queued parameter changes are public; position before execution.
- **Multisig/member change** — Squads threshold/member edits, or governance proposal with hidden ix.

## Phase 5: Deprecation & Wind-down
- **Residual funds in deprecated accounts/PDAs** — old PDAs still hold tokens; keepers stopped.
- **Abandoned delegations/approvals** — users' token-account delegations to old program PDAs.
- **Dependent-program breakage** — others CPI into the deprecated program and get stale data/reverts.
- **Frozen config** — if the upgrade/admin authority is lost, parameters can't adapt to new conditions.

## Writing the Temporal Risk Profile
Include phases that add NEW info beyond Actors/Attack Surfaces/Upgrade Architecture. 1-3 bullets per phase,
each citing a code location and a mitigation status. Skip Phase 2.

---

# Cross-Program Composability Threats

Solana's defining property is composability via **CPI** and shared accounts. Classify each external call
and shared dependency into the threat taxonomy.

## External Call (CPI) Classification
For each CPI / external program dependency found in Step 2, determine:
1. **Target type**: Oracle (Pyth/Switchboard), DEX/AMM, Lending, Token program (SPL/Token-2022),
   Stake pool, Governance, Bridge, Other.
2. **Program-id pinned?**: typed `Program<T>`/`Interface<T>`/`address =`, or raw `AccountInfo` (arbitrary
   CPI — `solana-vulns.md` §4)?
3. **Assumptions about result**: correct price, exact amount transferred, success, account state.
4. **Validation present**: staleness/confidence (oracle), balance-delta (token), key/owner checks.
5. **Mutability**: is the callee upgradeable? Governed? Can its behavior change without consent?
6. **On failure**: revert, fail-open, or fallback value?

## Layer 1: Direct Dependency Risks
- **Oracle dependency chain** — Pyth/Switchboard: is `updatedAt`/publish-time checked
  (`get_price_no_older_than`)? Confidence interval bounded? Zero/negative handled? Right feed for the
  asset? Fallback also validated? On L2-like setups n/a, but **stale/again-confidence** is the Solana
  equivalent of EVM oracle staleness.
- **Token behavior assumptions (SPL + Token-2022)** — the Solana token-quirk matrix:

| Assumption | Holds for | Violated by | Impact |
|---|---|---|---|
| Transfer moves exact amount | SPL Token | **Token-2022 transfer fee** | received < sent → accounting > real balance |
| Balance changes only via transfer | SPL Token | rebasing/interest-bearing (Token-2022 ext, stake-pool tokens) | accounting drift, share manipulation |
| No callback on transfer | SPL Token | **Token-2022 transfer hook** | arbitrary CPI mid-transfer → reentrancy |
| Fixed decimals | per-mint | different mints (USDC=6, most=9, WBTC=8) | scale errors, mis-valuation |
| Account can't be frozen | most | freeze authority / default-frozen (Token-2022) | funds frozen, ops blocked |
| Mint is immutable | most | upgradeable mint authority / permanent delegate (Token-2022) | behavior changes post-deploy |
| Owner controls the account | SPL | permanent delegate (Token-2022) | third party moves funds |

  Look for: `transfer_checked` vs `transfer`; before/after balance-delta + `reload` (fee handling);
  `mint`/`authority` constraints on token accounts; hardcoded decimals; whether arbitrary mints are
  accepted or a whitelist is enforced.
- **CPI callback reentrancy** — Token-2022 transfer hooks, and any CPI to a program that can re-enter this
  one before state is finalized. Per-handler reentrancy is possible on Solana via CPI even though there's
  no shared global state across txs. Look for state writes after CPIs (checks-effects-interactions), and
  missing reentrancy guards on hook-bearing token paths.

## Layer 2: Shared State Risks
- **Liquidity / pool coupling** — this program and others swap through or price off the same Raydium/Orca
  pool; a large action here moves price there within a slot.
- **Oracle sharing** — same Pyth feed used by major lending/perps protocols → correlated liquidations.
- **Shared PDA / ATA exposure** — token-account delegations to program PDAs; if an upgrade adds a draining
  ix, delegated funds are exposed. Deprecated PDAs holding delegations.

## Layer 3: Temporal Composability Risks
- **Governance-induced change** — a dependency's governance changes a parameter this program assumes
  (e.g. a lending market's collateral factor) — no ix changed, economics broke.
- **Upgrade-induced behavior change** — a CPI callee is upgraded (same id, new behavior). Are callees
  upgradeable? Does error handling assume specific revert/return shapes?
- **Deprecation without notification** — a consumed oracle/pool is deprecated; calls return stale data or
  start failing; does the fallback fail-open (stale) or fail-closed (revert)?
- **Dependency-of-dependency** — this → A → B; B upgrades, A's behavior changes, this breaks. Map chains
  2-3 levels; flag chains deeper than 2 where callees are upgradeable/governed.
