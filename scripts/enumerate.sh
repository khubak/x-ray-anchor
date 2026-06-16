#!/bin/bash
# Step 1: Enumerate Rust/Solana/Anchor source, line counts, nSLOC, test & fuzz stats,
# Solana-specific config signals, docs, commit, and git history stats.
# Usage: enumerate.sh <project-root> [src-dir]
# Output: labeled `=== name ===` sections consumed by the x-ray-anchor skill.

set -e
ROOT="${1:-.}"
SRC="${2:-}"

cd "$ROOT"

# Auto-detect source dir if not provided: Anchor uses programs/<name>/src; native uses src/.
if [ -z "$SRC" ]; then
  if [ -d programs ]; then SRC="programs"
  elif [ -d src ]; then SRC="src"
  else SRC="."; fi
fi

# Shared find filter for first-party Rust source (excludes build artifacts and tests).
find_src() {
  find "$SRC" -name '*.rs' \
    -not -path '*/target/*' -not -path '*/tests/*' -not -path '*/test/*' \
    -not -path '*/trident-tests/*' -not -path '*/.anchor/*' \
    -not -path '*/node_modules/*' -not -path '*/fuzz/*' \
    -not -path '*/.cargo/*' 2>/dev/null | sort
}

# ─── Toolchain ────────────────────────────────────────────────────────────────

echo "=== Toolchain ==="
if [ -f Anchor.toml ]; then echo "anchor"
elif grep -rqsE '^\s*solana-program\s*=|^\s*anchor-lang\s*=' Cargo.toml 2>/dev/null || \
     ls programs/*/Cargo.toml >/dev/null 2>&1; then echo "native"
elif [ -f Cargo.toml ]; then echo "cargo"
else echo "unknown"; fi

# ─── Anchor program IDs (declare_id! / Anchor.toml) ──────────────────────────

echo "=== program_ids ==="
grep -rhoP 'declare_id!\("\K[^"]+' "$SRC" --include='*.rs' 2>/dev/null | sort -u || true

# ─── Source files with line counts ────────────────────────────────────────────

echo "=== Source (with line counts) ==="
find_src | xargs wc -l 2>/dev/null

# ─── nSLOC (non-blank, non-comment lines) per file ───────────────────────────
# Rust shares C-style comments with Solidity: // /// //! /* * */

echo "=== nSLOC ==="
sum=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  t=$(grep -cP '\S' "$f" || true)
  c=$(grep -cP '^\s*(//|/\*|\*|\*/)' "$f" || true)
  n=$((t - c))
  printf "%s: %d\n" "$f" "$n"
  sum=$((sum + n))
done < <(find_src)
echo "TOTAL: $sum"

# ─── Doc comments (Rust /// //! /** /*!) ─────────────────────────────────────

echo "=== doc_comments ==="
grep -rcP '^\s*///|^\s*//!|/\*\*|/\*!' "$SRC" --include='*.rs' \
  --exclude-dir=target --exclude-dir=tests --exclude-dir=trident-tests 2>/dev/null \
  | awk -F: '{s+=$NF}END{print s+0}'

# ─── Solana-specific config / safety signals ─────────────────────────────────

# overflow-checks: Rust release mode WRAPS by default; Solana programs build in
# release, so `overflow-checks = true` is a security-critical config signal.
echo "=== overflow_checks ==="
if grep -rqsP '^\s*overflow-checks\s*=\s*true' Cargo.toml programs/*/Cargo.toml 2>/dev/null; then
  echo "enabled"
elif find . -maxdepth 3 -name 'Cargo.toml' -not -path '*/target/*' 2>/dev/null | xargs grep -lsP '^\s*overflow-checks\s*=\s*true' 2>/dev/null | head -1 | grep -q .; then
  echo "enabled"
else
  echo "not_found"
fi

# init_if_needed: reinitialization attack surface (Anchor feature + usage).
echo "=== init_if_needed ==="
grep -rcP 'init_if_needed' "$SRC" --include='*.rs' --exclude-dir=target 2>/dev/null \
  | awk -F: '{s+=$NF}END{print s+0}'

# unchecked accounts: manual-validation surface (UncheckedAccount / AccountInfo / CHECK).
echo "=== unchecked_accounts ==="
grep -rcP 'UncheckedAccount|AccountInfo<|/// CHECK|//\s*CHECK' "$SRC" --include='*.rs' --exclude-dir=target 2>/dev/null \
  | awk -F: '{s+=$NF}END{print s+0}'

# unsafe blocks.
echo "=== unsafe_blocks ==="
grep -rcP '\bunsafe\b' "$SRC" --include='*.rs' --exclude-dir=target 2>/dev/null \
  | awk -F: '{s+=$NF}END{print s+0}'

# ─── Tests ────────────────────────────────────────────────────────────────────
# Test PRESENCE is file-scan and ALWAYS reliable, independent of whether the
# toolchain can build. Coverage execution is separate and best-effort.

echo "=== test_files ==="
# Rust files with test attributes (inline #[cfg(test)] or test fns) + TS/JS under tests/.
RS_TEST_FILES=$(grep -rlP '#\[cfg\(test\)\]|#\[tokio::test\]|#\[test\]' . --include='*.rs' \
  --exclude-dir=target --exclude-dir=node_modules 2>/dev/null | wc -l)
TS_TEST_FILES=$(find . \( -name '*.ts' -o -name '*.js' -o -name '*.mts' -o -name '*.mjs' \) \
  \( -path '*/tests/*' -o -path '*/test/*' \) \
  -not -path '*/node_modules/*' -not -path '*/target/*' -not -path '*/.anchor/*' \
  -not -path '*/dist/*' 2>/dev/null | wc -l)
echo $((RS_TEST_FILES + TS_TEST_FILES))

echo "=== test_functions ==="
# Rust: #[test] + #[tokio::test]. TS: it()/test() blocks (mocha/jest/vitest).
RS_TESTS=$(grep -rcP '#\[(tokio::)?test\]' . --include='*.rs' \
  --exclude-dir=target --exclude-dir=node_modules 2>/dev/null | awk -F: '{s+=$NF}END{print s+0}')
TS_TESTS=$(grep -rcP '^\s*(it|test)(\.(only|skip|concurrent))?\s*\(' . \
  --include='*.ts' --include='*.js' --include='*.mts' --include='*.mjs' \
  --exclude-dir=node_modules --exclude-dir=target --exclude-dir=dist 2>/dev/null \
  | grep -iP '/(tests?|specs?)/' | awk -F: '{s+=$NF}END{print s+0}')
echo $((RS_TESTS + TS_TESTS))

# ── Rust unit/integration test functions ──
echo "=== rust_unit ==="
grep -rcP '#\[(tokio::)?test\]' . --include='*.rs' \
  --exclude-dir=target --exclude-dir=node_modules 2>/dev/null | awk -F: '{s+=$NF}END{print s+0}'

# ── TS integration tests (it/describe under tests/) ──
echo "=== ts_integration ==="
grep -rcP '^\s*(it|test|describe)(\.(only|skip|concurrent))?\s*\(' . \
  --include='*.ts' --include='*.js' --include='*.mts' --include='*.mjs' \
  --exclude-dir=node_modules --exclude-dir=target --exclude-dir=dist 2>/dev/null \
  | grep -iP '/(tests?|specs?)/' | awk -F: '{s+=$NF}END{print s+0}'

# ── Local validator harnesses: bankrun / litesvm / solana-program-test / mollusk ──
echo "=== litesvm_bankrun ==="
LSB_FUNCS=$(grep -rcP 'litesvm|solana-bankrun|anchor-bankrun|solana_program_test|ProgramTest|mollusk' . \
  --include='*.rs' --include='*.ts' --include='*.js' \
  --exclude-dir=node_modules --exclude-dir=target 2>/dev/null | awk -F: '{s+=$NF}END{print s+0}')
LSB_CONF=$(grep -rlsP 'litesvm|solana-bankrun|anchor-bankrun|solana-program-test|mollusk' \
  Cargo.toml programs/*/Cargo.toml package.json 2>/dev/null | wc -l)
echo "${LSB_FUNCS}:${LSB_CONF}"

# ── Trident fuzzing (Ackee) ──
echo "=== trident ==="
TRIDENT_FUNCS=$(grep -rcP 'trident_fuzz|use trident|#\[derive\(.*FuzzTestExecutor|fuzz_ix|FuzzInstruction' . \
  --include='*.rs' --exclude-dir=target 2>/dev/null | awk -F: '{s+=$NF}END{print s+0}')
TRIDENT_CONF=$(find . -maxdepth 3 \( -name 'Trident.toml' -o -name 'trident.toml' \) 2>/dev/null | wc -l)
TRIDENT_DIR=$(find . -maxdepth 2 -type d -name 'trident-tests' 2>/dev/null | wc -l)
echo "${TRIDENT_FUNCS}:$((TRIDENT_CONF + TRIDENT_DIR))"

# ── cargo-fuzz (libFuzzer) ──
echo "=== cargo_fuzz ==="
CF_FUNCS=$(grep -rcP 'fuzz_target!' . --include='*.rs' --exclude-dir=target 2>/dev/null | awk -F: '{s+=$NF}END{print s+0}')
CF_DIR=$(find . -maxdepth 2 -type d -name 'fuzz' 2>/dev/null | wc -l)
echo "${CF_FUNCS}:${CF_DIR}"

# ── Property testing: proptest / quickcheck ──
echo "=== proptest ==="
grep -rcP 'proptest!|#\[quickcheck\]|prop_assert' . --include='*.rs' --exclude-dir=target 2>/dev/null \
  | awk -F: '{s+=$NF}END{print s+0}'

# ── Formal verification: Kani / Certora Solana ──
echo "=== kani ==="
KANI_FUNCS=$(grep -rcP '#\[kani::proof\]|kani::' . --include='*.rs' --exclude-dir=target 2>/dev/null | awk -F: '{s+=$NF}END{print s+0}')
CERTORA_CONF=$(find . \( -name '*.spec' -o -name '*.conf' -path '*certora*' \) 2>/dev/null | grep -v node_modules | grep -v '/target/' | wc -l)
echo "${KANI_FUNCS}:${CERTORA_CONF}"

# ─── Docs ─────────────────────────────────────────────────────────────────────

echo "=== docs ==="
ls -d README.md README* docs/ doc/ whitepapers/ whitepaper/ spec/ specs/ paper/ papers/ audits/ 2>/dev/null || true

echo "=== commit ==="
git rev-parse --short HEAD 2>/dev/null || echo "unknown"

# ─── Git history stats ────────────────────────────────────────────────────────

echo "=== git_unique_authors ==="
git log --format='%aN' | sort -u | wc -l

echo "=== git_contributors ==="
git log --format='%aN' | sort | uniq -c | sort -rn

echo "=== git_source_contributors ==="
git log --numstat --format='COMMIT_BY:%aN' -- "$SRC" | \
  awk '/^COMMIT_BY:/{a=substr($0,11);next} NF==3 && $1~/[0-9]/{add[a]+=$1;del[a]+=$2} END{for(a in add)printf "%d\t%d\t%s\n",add[a],del[a],a}' | sort -rn

echo "=== git_repo_age ==="
git log --reverse --format='%aI' | head -1
git log -1 --format='%aI'

echo "=== git_total_commits ==="
git rev-list --count HEAD

echo "=== git_merge_count ==="
git log --merges --oneline | wc -l

echo "=== git_hotspots ==="
git log --name-only --format='' -- "$SRC" | grep -E '\.rs$' | sort | uniq -c | sort -rn | head -15

echo "=== git_recent_30d ==="
git log --since='30 days ago' --oneline -- "$SRC" | head -20

echo "=== git_large_diffs ==="
git log --format='COMMIT:%h %aN %s' --numstat -- "$SRC" | \
  awk '/^COMMIT:/{if(c && s>0)print s,c;c=$0;s=0;next} NF>=2 && $1~/[0-9]/{s+=$1+$2} END{if(c && s>0)print s,c}' | sort -rn | head -10
