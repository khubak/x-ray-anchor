# X-Ray Anchor

Know your Solana program before auditors do.

Built for:

- **Protocol teams** preparing for an audit — fix the obvious so auditors can focus on what matters
- **Security researchers** starting a new engagement — get the full picture in minutes

Not a vulnerability scanner — it's the briefing you read before opening the first `.rs` file.

## What You Get

One command produces an `x-ray/` folder:

| Output | What's Inside |
|--------|--------------|
| `x-ray.md` | Program overview, threat model, account-model attack surfaces, test/fuzz gaps, git history, readiness verdict |
| `entry-points.md` | Every instruction handler classified by access (permissionless / role-gated / admin / query) with signer, CPI chain, and accounts touched |
| `invariants.md` | Full invariant map — enforced guards & Anchor constraints, single-program invariants, cross-program/CPI trust assumptions, economic properties |
| `architecture.svg` | Visual architecture diagram — programs, PDAs, actors, external CPI targets |

## What's Solana-specific

- **Entry points** = `#[program]` instruction handlers (`pub fn … ctx: Context<…>`); native programs fall
  back to the instruction enum + `process_instruction`.
- **Access control** is read from `#[derive(Accounts)]` constraints — `Signer`, `has_one`, `constraint =`,
  `address =`, `#[access_control]` — plus in-body `require_keys_eq!` (e.g. two-step authority transfer).
- **Account-model vulnerability library** (`references/solana-vulns.md`) — missing signer/owner checks,
  PDA/bump issues, arbitrary CPI, account revival on close, `init_if_needed` reinit, duplicate accounts,
  sysvar spoofing, integer overflow (Rust release wraps), Token-2022 transfer fees/hooks, and more. Every
  `UncheckedAccount` / `/// CHECK:` site is flagged as a manual-validation surface.
- **Tests & fuzzing** detected by file scan: Rust unit, `solana-bankrun`/`anchor-bankrun`/`litesvm`/
  `solana-program-test`/`mollusk`, **Trident** fuzzing, `cargo-fuzz`, `proptest`, **Kani**.
- **Dependencies** — forked/overridden Cargo deps (git/path/`[patch]`) are flagged as hidden attack
  surface, the Solana analog of internalized EVM libraries.
- **Upgradeability** — surfaces who holds the program's upgrade authority and mint authority (the highest-
  leverage centralization surfaces).

## Requirements

- `git`, `python3`, and `bash` (for the enumeration script). No third-party Python packages.
- `cargo-llvm-cov` is optional — coverage is best-effort and frequently unavailable on Solana; test
  *existence* is always determined by file scan regardless.

## Usage

Install (copy the folder into your skills directory):

```
~/.claude/skills/x-ray-anchor/
```

Then, in a Solana/Anchor repo:

```
x-ray-anchor
```

or "x-ray this anchor program" / "pre-audit this solana program".

## Tips

- **Start with the verdict.** The report ends with a tier (FORTIFIED → EXPOSED) and structural facts. If
  you read one section, read that.
- **Use entry-points.md as your map.** Start with permissionless instructions — the highest-risk surface —
  then the `UncheckedAccount` / `CHECK:` sites called out in Key Attack Surfaces.
- **The On-chain=No invariants are the high-signal ones** — each is simultaneously an invariant and a
  candidate bug.
