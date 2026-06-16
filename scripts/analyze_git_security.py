#!/usr/bin/env python3
"""Git history security analysis for Rust / Solana / Anchor repositories.

Analyzes git history from a security researcher's perspective: fix commits,
dangerous area changes, forked/overridden Cargo dependencies, technical debt,
and developer patterns. Outputs structured JSON consumed by the x-ray-anchor skill.

Usage:
    python3 analyze_git_security.py --repo . --src-dir programs
    python3 analyze_git_security.py --repo . --src-dir programs/onreapp/src --json /tmp/out.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


# ═══════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════

@dataclass
class FileChange:
    path: str
    added: int
    deleted: int
    is_source: bool = False
    is_test: bool = False


@dataclass
class Commit:
    sha: str
    short_sha: str
    date: str
    author: str
    subject: str
    files: list[FileChange] = field(default_factory=list)
    is_merge: bool = False

    @property
    def source_files(self) -> list[FileChange]:
        return [f for f in self.files if f.is_source]

    @property
    def test_files(self) -> list[FileChange]:
        return [f for f in self.files if f.is_test]

    @property
    def total_churn(self) -> int:
        return sum(f.added + f.deleted for f in self.files)

    @property
    def source_churn(self) -> int:
        return sum(f.added + f.deleted for f in self.files if f.is_source)


# ═══════════════════════════════════════════════════════════════
# COMMIT CLASSIFICATION — Intent + Structural Impact model
#
# Two-phase approach:
#   Phase 1: Classify commit MESSAGE into a single intent category
#            (first match wins from priority-ordered rules)
#   Phase 2: Analyze DIFF structure for directional code changes
#            (net addition of guards, removal of code paths, etc.)
#
# Final score = intent_base + structural_impact + shape_modifier
#               + security_domain_overlap
# ═══════════════════════════════════════════════════════════════

# Primary intent: first match wins, sets the base score
_INTENT_RULES: list[tuple[str, list[re.Pattern], int, str]] = [
    ("security_explicit", [
        re.compile(r"\b(security|vulnerab|exploit|attack|CVE-\d|unsound|soundness)\b", re.I),
        re.compile(r"\b(reentran|overflow|underflow|front.?run|malleab)\w*", re.I),
        re.compile(r"\b(missing\s+(signer|owner)|signer\s+check|owner\s+check|type\s+cosplay)\b", re.I),
    ], 8, "explicit security language"),

    ("urgent_fix", [
        re.compile(r"\b(hotfix|emergency|critical|IMPT)\b", re.I),
    ], 6, "urgent/critical fix"),

    ("bug_fix", [
        re.compile(r"\bfix(es|ed)?\b", re.I),
        re.compile(r"\bbug\b", re.I),
        re.compile(r"\bpatch\b", re.I),
        re.compile(r"\bbroken\b", re.I),
    ], 4, "bug fix"),

    ("hardening", [
        re.compile(r"\b(harden|mitigat|protect|restrict|sanitiz|validat|constrain)\w*", re.I),
    ], 2, "hardening/validation"),

    ("feature", [
        re.compile(r"^\s*(feat|add|implement|introduce|support)\b", re.I),
    ], -1, "feature addition"),

    ("maintenance", [
        re.compile(r"^\s*(docs?|chore|ci|test|style|build)\s*:", re.I),
        re.compile(r"\b(readme|typo|format|lint|clippy|fmt|rename|refactor|cleanup|comment)\b", re.I),
        re.compile(r"\bchange\s+\w+\s+to\s+\w+\b", re.I),
    ], -3, "maintenance/cosmetic"),
]

# Topic tags: independent domain signals (Solana-flavored). Each adds +2.
_TOPIC_TAGS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b(oracle|price|liquidat|slippage|nav|pyth|switchboard|MEV)\w*", re.I),
     "involves oracle/pricing"),
    (re.compile(r"\b(reentran|overflow|underflow|cpi|pda|sysvar|realloc|close)\w*", re.I),
     "involves known vulnerability pattern"),
    (re.compile(r"\b(ed25519|secp256k1|signature|nonce|approval|seeds|bump|signer)\w*", re.I),
     "involves signatures/auth"),
]


def _classify_intent(subject: str) -> tuple[int, list[str]]:
    primary_score = 0
    reasons: list[str] = []
    primary_cat = None
    for cat, patterns, base_score, reason in _INTENT_RULES:
        if any(p.search(subject) for p in patterns):
            primary_score = base_score
            reasons.append(reason)
            primary_cat = cat
            break

    if primary_cat is None:
        reasons.append("unclassified")

    if primary_score >= 0:
        for pattern, tag_reason in _TOPIC_TAGS:
            if pattern.search(subject) and tag_reason not in reasons:
                if primary_cat != "security_explicit" or "vulnerability pattern" not in tag_reason:
                    primary_score += 2
                    reasons.append(tag_reason)

    return primary_score, reasons


# Phase 2: Structural diff analysis — Anchor/Rust constructs.
# Guards: require!/require_eq!/require_keys_eq!/assert!/return Err/.ok_or
_GUARD_ADD = re.compile(
    r"^\+[^+].*\b(require(_\w+)?!|assert(_\w+)?!|return\s+Err|\.ok_or)\s*[!(]?", re.M)
_GUARD_REM = re.compile(
    r"^-[^-].*\b(require(_\w+)?!|assert(_\w+)?!|return\s+Err|\.ok_or)\s*[!(]?", re.M)
# Access control: Anchor Accounts constraints + signer checks
_MOD_ADD = re.compile(
    r"^\+[^+].*(\bSigner\s*<|has_one\s*=|constraint\s*=|#\[access_control"
    r"|\baddress\s*=|init_if_needed|require_keys_eq!|is_signer\b)", re.M)
_MOD_REM = re.compile(
    r"^-[^-].*(\bSigner\s*<|has_one\s*=|constraint\s*=|#\[access_control"
    r"|\baddress\s*=|init_if_needed|require_keys_eq!|is_signer\b)", re.M)
# Token movement / CPI / lamport transfers
_XFER_CHANGE = re.compile(
    r"^[+-][^+-].*\b(transfer_checked|token(_interface)?::transfer|mint_to|burn"
    r"|invoke_signed|invoke\b|CpiContext|try_borrow_mut_lamports|system_program::transfer)", re.M)
# Signature / auth / PDA-signing handling
_SIG_CHANGE = re.compile(
    r"^[+-][^+-].*\b(ed25519|secp256k1|sysvar::instructions|load_instruction"
    r"|invoke_signed|verify\w*approval|\bseeds\s*=|\bbump\b)", re.M)
# Accounting / balance state
_ACCT_CHANGE = re.compile(
    r"^[+-][^+-].*\b(amount|supply|lamports|reserve|balance|exchange_rate|\bnav\b|\bprice\b)", re.M)


def _analyze_diff_structure(diff_text: str) -> list[tuple[int, str]]:
    results: list[tuple[int, str]] = []

    guards_added = len(_GUARD_ADD.findall(diff_text))
    guards_removed = len(_GUARD_REM.findall(diff_text))
    if guards_added > 0 or guards_removed > 0:
        if guards_added > guards_removed:
            results.append((3, f"adds runtime guards (+{guards_added}/-{guards_removed})"))
        elif guards_removed > guards_added:
            results.append((3, f"removes runtime guards (+{guards_added}/-{guards_removed})"))
        else:
            results.append((2, f"rewrites runtime guards (+{guards_added}/-{guards_removed})"))

    mods_added = len(_MOD_ADD.findall(diff_text))
    mods_removed = len(_MOD_REM.findall(diff_text))
    if mods_added > 0 or mods_removed > 0:
        if mods_added > mods_removed:
            results.append((3, f"tightens account/access constraints (+{mods_added}/-{mods_removed})"))
        elif mods_removed > mods_added:
            results.append((3, f"loosens account/access constraints (+{mods_added}/-{mods_removed})"))
        else:
            results.append((2, f"rewrites account/access constraints (+{mods_added}/-{mods_removed})"))

    if _XFER_CHANGE.search(diff_text):
        results.append((2, "changes token/CPI/lamport transfer logic"))

    if _SIG_CHANGE.search(diff_text):
        results.append((2, "changes signature/PDA-seed handling"))

    if _ACCT_CHANGE.search(diff_text):
        results.append((1, "changes accounting/balance logic"))

    return results


# ═══════════════════════════════════════════════════════════════
# SECURITY AREA CLASSIFICATION (Solana / Anchor)
# ═══════════════════════════════════════════════════════════════

SECURITY_AREAS = {
    "access_control": [
        r"\bSigner\s*<", r"has_one\s*=", r"constraint\s*=", r"#\[access_control",
        r"require_keys_eq!", r"assert_keys_eq", r"\bis_signer\b", r"\.owner\b",
        r"\bauthority\b", r"only_\w+", r"\baddress\s*=",
    ],
    "fund_flows": [
        r"transfer_checked", r"token(_interface)?::transfer", r"\bmint_to\b",
        r"\bburn\b", r"CpiContext", r"try_borrow_mut_lamports", r"\blamports\b",
        r"system_program::transfer", r"fn\s+deposit", r"fn\s+withdraw", r"\bvault\b",
    ],
    "oracle_price": [
        r"\bpyth\b", r"switchboard", r"get_price", r"price_no_older_than",
        r"\boracle\b", r"\bnav\b", r"\bprice\b", r"\bfeed\b", r"twap",
    ],
    "liquidation": [
        r"liquidat", r"\bhealth\b", r"collateral", r"bad_debt", r"insolven",
        r"backstop", r"deleverage", r"isLiquidatable",
    ],
    "signatures": [
        r"ed25519", r"secp256k1", r"sysvar.{0,3}instructions", r"invoke_signed",
        r"\bseeds\s*=", r"\bbump\b", r"verify\w*approval", r"\bnonce\b", r"ecdsa",
        r"load_instruction",
    ],
    "state_machines": [
        r"is_killed", r"kill_switch", r"\bpaused\b", r"\bfrozen\b", r"\bstatus\b",
        r"\bstate\b\s*\.", r"lifecycle", r"transition", r"\bPhase\b", r"\bStage\b",
        r"is_active", r"when_not_paused",
    ],
}

_AREA_COMPILED = {
    area: [re.compile(p) for p in patterns]
    for area, patterns in SECURITY_AREAS.items()
}

# ═══════════════════════════════════════════════════════════════
# KNOWN CRATES (Solana ecosystem)
# ═══════════════════════════════════════════════════════════════

KNOWN_LIBS = {
    "anchor-lang": "Anchor (anchor-lang)",
    "anchor-spl": "Anchor SPL (anchor-spl)",
    "solana-program": "Solana Program",
    "spl-token": "SPL Token",
    "spl-token-2022": "SPL Token-2022",
    "spl-associated-token-account": "SPL Associated Token Account",
    "mpl-token-metadata": "Metaplex Token Metadata",
    "mpl-bubblegum": "Metaplex Bubblegum (cNFT)",
    "pyth-sdk-solana": "Pyth",
    "pyth-solana-receiver-sdk": "Pyth (receiver)",
    "switchboard-v2": "Switchboard V2",
    "switchboard-on-demand": "Switchboard On-Demand",
    "jupiter-amm-interface": "Jupiter",
    "clockwork-sdk": "Clockwork",
}

# ═══════════════════════════════════════════════════════════════
# PATH CLASSIFICATION
# ═══════════════════════════════════════════════════════════════

SOURCE_SUFFIXES = (".rs",)
TEST_HINTS = (
    "/tests/", "/test/", "trident-tests/", "/fuzz/", "__tests__/",
    ".test.", ".spec.", "/benches/",
)
EXCLUDE_DIRS = (
    "/target/", "/node_modules/", "/.anchor/", "/dist/", "/.cargo/",
)


def classify_path(path: str, src_dir: str) -> tuple[bool, bool]:
    """Classify a path as (is_source, is_test)."""
    lowered = "/" + path.lower()
    is_test = any(hint in lowered for hint in TEST_HINTS)

    if not any(path.endswith(s) for s in SOURCE_SUFFIXES):
        return False, is_test

    if any(exc in f"/{path}" for exc in EXCLUDE_DIRS):
        return False, is_test

    is_source = path.startswith(src_dir) and not is_test
    return is_source, is_test


def find_source_files(repo: str, src_dir: str) -> list[str]:
    """Walk filesystem for current .rs files in src_dir."""
    result = []
    src_path = os.path.join(repo, src_dir)
    if not os.path.isdir(src_path):
        return result
    for root, dirs, files in os.walk(src_path):
        dirs[:] = [d for d in dirs if d not in (
            "target", "tests", "test", "trident-tests", "node_modules",
            ".anchor", "fuzz", "benches", ".cargo",
        )]
        for fname in files:
            if fname.endswith(".rs"):
                rel = os.path.relpath(os.path.join(root, fname), repo)
                result.append(rel.replace("\\", "/"))
    return sorted(result)


# ═══════════════════════════════════════════════════════════════
# GIT DATA COLLECTION
# ═══════════════════════════════════════════════════════════════

def run_git(repo: str, *args: str, allow_fail: bool = False) -> str:
    # Force UTF-8 decoding with replacement: git output (author names, diffs) is
    # UTF-8, but Windows subprocess otherwise defaults to the locale codepage
    # (cp1252) and raises UnicodeDecodeError on bytes undefined there.
    cmd = ["git", "-C", repo] + list(args)
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="utf-8", errors="replace", check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError:
        if allow_fail:
            return ""
        raise


def parse_git_log(repo: str, src_dir: str) -> list[Commit]:
    """Parse full git history in a single call."""
    sep = "<<SEP>>"
    fmt = f"COMMIT_START{sep}%H{sep}%h{sep}%aI{sep}%aN{sep}%P{sep}%s"
    raw = run_git(repo, "log", "--numstat", f"--format={fmt}")

    commits = []
    current: Commit | None = None
    for line in raw.splitlines():
        if line.startswith(f"COMMIT_START{sep}"):
            if current is not None:
                commits.append(current)
            parts = line.split(sep)
            if len(parts) < 7:
                current = None
                continue
            _, sha, short, date, author, parents, subject = parts[:7]
            is_merge = " " in parents.strip()
            current = Commit(
                sha=sha, short_sha=short, date=date[:10],
                author=author, subject=subject, is_merge=is_merge,
            )
        elif current is not None and line.strip():
            parts = line.split("\t")
            if len(parts) >= 3:
                try:
                    added = int(parts[0]) if parts[0] != "-" else 0
                    deleted = int(parts[1]) if parts[1] != "-" else 0
                except ValueError:
                    continue
                path = parts[2].replace("\\", "/")
                is_src, is_tst = classify_path(path, src_dir)
                current.files.append(FileChange(
                    path=path, added=added, deleted=deleted,
                    is_source=is_src, is_test=is_tst,
                ))

    if current is not None:
        commits.append(current)
    return commits


# ═══════════════════════════════════════════════════════════════
# SECTION 1: REPO SHAPE
# ═══════════════════════════════════════════════════════════════

def analyze_repo_shape(commits: list[Commit], src_dir: str) -> dict:
    if not commits:
        return {
            "classification": "empty",
            "total_commits": 0,
            "source_touching_commits": 0,
            "bulk_import_sha": None,
            "date_spread_days": 0,
            "first_commit_date": None,
            "last_commit_date": None,
            "signals": ["Empty repository"],
        }

    source_commits = [c for c in commits if c.source_files]
    dates = sorted(c.date for c in commits)
    first = dates[0]
    last = dates[-1]

    try:
        d1 = datetime.strptime(first, "%Y-%m-%d")
        d2 = datetime.strptime(last, "%Y-%m-%d")
        spread = (d2 - d1).days
    except ValueError:
        spread = 0

    bulk_sha = None
    signals = []
    total_source_added = sum(
        sum(f.added for f in c.source_files)
        for c in source_commits
    )
    if source_commits:
        biggest = max(source_commits, key=lambda c: sum(f.added for f in c.source_files))
        biggest_added = sum(f.added for f in biggest.source_files)
        if total_source_added > 0 and biggest_added / total_source_added > 0.85:
            bulk_sha = biggest.short_sha
            signals.append(
                f"~{biggest_added} source lines arrived in 1 commit ({bulk_sha})"
            )

    classification = "normal_dev"
    if len(source_commits) <= 1:
        classification = "squashed_import"
        signals.append("Only 1 commit touches source files")
    elif len(source_commits) <= 3 and spread < 7:
        classification = "squashed_import"
        signals.append(f"Only {len(source_commits)} source commits in {spread} days")

    if bulk_sha and classification == "normal_dev":
        signals.append("Bulk import detected with subsequent development")

    signals.append(f"Date spread: {spread} days")
    signals.append(f"{len(source_commits)} commits touch source files out of {len(commits)} total")

    return {
        "classification": classification,
        "total_commits": len(commits),
        "source_touching_commits": len(source_commits),
        "bulk_import_sha": bulk_sha,
        "date_spread_days": spread,
        "first_commit_date": first,
        "last_commit_date": last,
        "signals": signals,
    }


# ═══════════════════════════════════════════════════════════════
# SECTION 2: FIX CANDIDATES
# ═══════════════════════════════════════════════════════════════

def score_commit(
    commit: Commit,
    src_dir: str,
    diff_text: str = "",
    file_areas_cache: dict[str, list[str]] | None = None,
) -> tuple[int, list[str]]:
    reasons: list[str] = []

    intent_score, intent_reasons = _classify_intent(commit.subject)
    reasons.extend(intent_reasons)

    src_files = commit.source_files
    if not src_files:
        return max(intent_score, 0), reasons

    structural_score = 0
    if diff_text:
        for delta, reason in _analyze_diff_structure(diff_text):
            structural_score += delta
            reasons.append(reason)

    domain_score = 0
    if file_areas_cache is not None:
        touched_domains: set[str] = set()
        for fc in src_files:
            for area in file_areas_cache.get(fc.path, []):
                touched_domains.add(area)
        if len(touched_domains) >= 2:
            domain_score = 3
            reasons.append(
                f"spans {len(touched_domains)} security domains "
                f"({', '.join(sorted(touched_domains))})"
            )
        elif len(touched_domains) == 1:
            domain_score = 1
            reasons.append(f"touches {next(iter(touched_domains))} code")

    shape_score = 0
    if 1 <= len(src_files) <= 3:
        shape_score += 2
        reasons.append(f"focused change ({len(src_files)} source files)")

    net_deleted = sum(f.deleted - f.added for f in src_files)
    if net_deleted > 0:
        shape_score += 1
        reasons.append("net code removal")

    src_churn = commit.source_churn
    if src_churn > 2000:
        shape_score -= 4
        reasons.append("very large change (>2000 source lines)")
    elif src_churn > 500:
        shape_score -= 2
        reasons.append("large change (>500 source lines)")

    if commit.test_files:
        shape_score += 1
        reasons.append("includes test changes")

    total = intent_score + structural_score + domain_score + shape_score
    return max(total, 0), _unique(reasons)


def find_fix_candidates(
    commits: list[Commit],
    src_dir: str,
    repo: str,
    limit: int,
    file_areas_cache: dict[str, list[str]] | None = None,
) -> list[dict]:
    candidates = []
    for commit in commits:
        if commit.is_merge:
            continue
        diff_text = ""
        if commit.source_files:
            diff_text = run_git(
                repo, "show", "--format=", "--unified=0",
                "--no-ext-diff", commit.sha,
                allow_fail=True,
            )
        sc, reasons = score_commit(
            commit, src_dir, diff_text, file_areas_cache,
        )
        if sc > 0:
            candidates.append({
                "sha": commit.short_sha,
                "full_sha": commit.sha,
                "date": commit.date,
                "author": commit.author,
                "subject": commit.subject,
                "score": sc,
                "reasons": reasons,
                "source_files_touched": [f.path for f in commit.source_files],
                "test_changed": bool(commit.test_files),
                "lines_changed": commit.source_churn,
            })

    candidates.sort(key=lambda c: (c["score"], c["date"]), reverse=True)
    if limit > 0:
        candidates = candidates[:limit]
    return candidates


# ═══════════════════════════════════════════════════════════════
# SECTION 3: DANGEROUS AREA CHANGES
# ═══════════════════════════════════════════════════════════════

def _read_file_safe(path: str) -> str:
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except (OSError, IOError):
        return ""


def classify_file_areas(content: str) -> list[str]:
    areas = []
    for area, patterns in _AREA_COMPILED.items():
        for pat in patterns:
            if pat.search(content):
                areas.append(area)
                break
    return areas


def _build_file_areas_cache(repo: str, src_dir: str) -> dict[str, list[str]]:
    cache: dict[str, list[str]] = {}
    src_path = os.path.join(repo, src_dir)
    if os.path.isdir(src_path):
        for root, dirs, files in os.walk(src_path):
            dirs[:] = [d for d in dirs if d not in (
                "target", "tests", "test", "trident-tests", "node_modules",
                ".anchor", "fuzz", "benches",
            )]
            for fname in files:
                if fname.endswith(".rs"):
                    full = os.path.join(root, fname)
                    rel = os.path.relpath(full, repo).replace("\\", "/")
                    content = _read_file_safe(full)
                    cache[rel] = classify_file_areas(content)
    return cache


def analyze_dangerous_areas(
    commits: list[Commit],
    src_dir: str,
    repo: str,
    file_areas_cache: dict[str, list[str]] | None = None,
) -> dict:
    if file_areas_cache is None:
        file_areas_cache = _build_file_areas_cache(repo, src_dir)

    result: dict[str, dict] = {}
    for area in SECURITY_AREAS:
        result[area] = {"commit_count": 0, "files": set(), "commits": []}

    for commit in commits:
        if commit.is_merge:
            continue
        commit_areas: set[str] = set()
        for fc in commit.files:
            areas = file_areas_cache.get(fc.path, [])
            for a in areas:
                commit_areas.add(a)
                result[a]["files"].add(fc.path)

        for a in commit_areas:
            result[a]["commit_count"] += 1
            result[a]["commits"].append({
                "sha": commit.short_sha,
                "date": commit.date,
                "subject": commit.subject[:80],
            })

    final = {}
    for area, data in result.items():
        if data["commit_count"] > 0:
            data["files"] = sorted(data["files"])
            if len(data["commits"]) > 15:
                data["commits"] = data["commits"][:15]
                data["truncated"] = True
            final[area] = data

    return final


# ═══════════════════════════════════════════════════════════════
# SECTION 4: LATE CHANGES
# ═══════════════════════════════════════════════════════════════

def analyze_late_changes(
    commits: list[Commit], src_dir: str, days: int
) -> dict:
    if not commits:
        return {
            "window_days": days, "cutoff_date": None, "latest_commit_date": None,
            "late_commits": [], "source_without_test_count": 0,
            "total_late_source_commits": 0,
        }

    dates = []
    for c in commits:
        try:
            dates.append(datetime.strptime(c.date, "%Y-%m-%d"))
        except ValueError:
            pass

    if not dates:
        return {
            "window_days": days, "cutoff_date": None, "latest_commit_date": None,
            "late_commits": [], "source_without_test_count": 0,
            "total_late_source_commits": 0,
        }

    latest = max(dates)
    cutoff = latest - timedelta(days=days)
    cutoff_str = cutoff.strftime("%Y-%m-%d")
    latest_str = latest.strftime("%Y-%m-%d")

    late = []
    no_test_count = 0
    for c in commits:
        try:
            cdate = datetime.strptime(c.date, "%Y-%m-%d")
        except ValueError:
            continue
        if cdate < cutoff:
            continue
        if not c.source_files:
            continue
        has_test = bool(c.test_files)
        if not has_test:
            no_test_count += 1
        late.append({
            "sha": c.short_sha,
            "date": c.date,
            "author": c.author,
            "subject": c.subject[:80],
            "source_files": [f.path for f in c.source_files][:10],
            "test_changed": has_test,
            "lines_changed": c.source_churn,
        })

    return {
        "window_days": days,
        "cutoff_date": cutoff_str,
        "latest_commit_date": latest_str,
        "late_commits": late,
        "source_without_test_count": no_test_count,
        "total_late_source_commits": len(late),
    }


# ═══════════════════════════════════════════════════════════════
# SECTION 5: FORKED / OVERRIDDEN CARGO DEPENDENCIES
#
# Solana analog of "internalized library = hidden attack surface":
#   - git deps (a crate pulled from a fork instead of crates.io)
#   - path deps (a local, possibly-modified vendored crate)
#   - [patch.*] overrides (silently replace a published crate with a fork —
#     the classic supply-chain risk; upstream security fixes won't propagate)
# ═══════════════════════════════════════════════════════════════

def _find_cargo_tomls(repo: str) -> list[str]:
    result = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in (
            "target", "node_modules", ".anchor", ".git", ".cargo",
        )]
        for fname in files:
            if fname == "Cargo.toml":
                result.append(os.path.join(root, fname))
    return sorted(result)


# crate-name = { git = "...", rev = "..." }   OR   crate-name = "1.2.3"
_DEP_INLINE = re.compile(
    r'^\s*([A-Za-z0-9_-]+)\s*=\s*\{(.+)\}\s*$')
_DEP_SIMPLE = re.compile(
    r'^\s*([A-Za-z0-9_-]+)\s*=\s*"([^"]+)"\s*$')
_KV = re.compile(r'(\w+)\s*=\s*"([^"]+)"')


def _parse_cargo_toml(path: str) -> dict:
    """Line-based parse: returns deps/patches by section. No toml lib needed."""
    git_deps, path_deps, patch_overrides, simple = [], [], [], []
    section = None
    rel = os.path.basename(os.path.dirname(path))
    try:
        with open(path, "r", errors="replace") as f:
            lines = f.readlines()
    except (OSError, IOError):
        return {"git": [], "path": [], "patch": [], "simple": []}

    for line in lines:
        s = line.strip()
        if s.startswith("[") and s.endswith("]"):
            section = s.strip("[]").strip()
            continue
        if not s or s.startswith("#"):
            continue
        is_dep_section = section and (
            "dependencies" in section or "build-dependencies" in section)
        is_patch = section and section.startswith("patch")

        m = _DEP_INLINE.match(line)
        if m:
            name, body = m.group(1), m.group(2)
            kvs = dict(_KV.findall(body))
            if is_patch:
                patch_overrides.append({
                    "name": name, "registry": section,
                    "source": kvs.get("git") or kvs.get("path") or "?",
                    "rev": kvs.get("rev") or kvs.get("branch") or kvs.get("tag"),
                    "from_file": rel,
                })
            elif is_dep_section:
                if "git" in kvs:
                    git_deps.append({
                        "name": name, "git": kvs["git"],
                        "rev": kvs.get("rev") or kvs.get("branch") or kvs.get("tag"),
                        "from_file": rel,
                    })
                elif "path" in kvs:
                    path_deps.append({
                        "name": name, "path": kvs["path"], "from_file": rel,
                    })
                elif "version" in kvs:
                    simple.append({"name": name, "version": kvs["version"], "from_file": rel})
            continue

        if is_dep_section:
            m2 = _DEP_SIMPLE.match(line)
            if m2:
                simple.append({"name": m2.group(1), "version": m2.group(2), "from_file": rel})

    return {"git": git_deps, "path": path_deps, "patch": patch_overrides, "simple": simple}


def analyze_forked_deps(repo: str) -> dict:
    git_deps, path_deps, patch_overrides, simple = [], [], [], []
    for toml in _find_cargo_tomls(repo):
        parsed = _parse_cargo_toml(toml)
        git_deps.extend(parsed["git"])
        path_deps.extend(parsed["path"])
        patch_overrides.extend(parsed["patch"])
        simple.extend(parsed["simple"])

    # Build a view of known security-critical crates and how they're sourced.
    sourced: dict[str, dict] = {}
    for d in simple:
        if d["name"] in KNOWN_LIBS and d["name"] not in sourced:
            sourced[d["name"]] = {"name": d["name"], "label": KNOWN_LIBS[d["name"]],
                                  "source_type": "crates.io", "detail": d["version"]}
    for d in git_deps:
        sourced[d["name"]] = {"name": d["name"],
                              "label": KNOWN_LIBS.get(d["name"], d["name"]),
                              "source_type": "git", "detail": d["git"], "rev": d.get("rev")}
    for d in path_deps:
        sourced[d["name"]] = {"name": d["name"],
                              "label": KNOWN_LIBS.get(d["name"], d["name"]),
                              "source_type": "path", "detail": d["path"]}
    for d in patch_overrides:
        sourced[d["name"]] = {"name": d["name"],
                              "label": KNOWN_LIBS.get(d["name"], d["name"]),
                              "source_type": "patch", "detail": d["source"], "rev": d.get("rev")}

    notes = []
    if patch_overrides:
        notes.append(f"{len(patch_overrides)} [patch] override(s) — published crates silently "
                     "replaced by forks; upstream security fixes will NOT auto-propagate")
    for d in git_deps:
        if d["name"] in KNOWN_LIBS:
            notes.append(f"{d['name']} pulled from git fork ({d['git']}) instead of crates.io")
    if path_deps:
        notes.append(f"{len(path_deps)} path (vendored/local) dependency(ies) — may contain "
                     "local modifications from upstream")

    return {
        "git_dependencies": git_deps,
        "path_dependencies": path_deps,
        "patch_overrides": patch_overrides,
        "known_critical": [sourced[k] for k in sorted(sourced)],
        "notes": notes,
    }


# ═══════════════════════════════════════════════════════════════
# SECTION 6: TECH DEBT
# ═══════════════════════════════════════════════════════════════

_DEBT_RE = re.compile(
    r"(?://|/\*)\s*(TODO|FIXME|HACK|XXX|SAFETY|AUDIT|BUG)\b[:\s]*(.*)",
    re.IGNORECASE,
)

BLAME_CAP = 20


def find_tech_debt(source_files: list[str], repo: str) -> dict:
    items = []
    files_with_debt = set()

    for rel_path in source_files:
        full_path = os.path.join(repo, rel_path)
        try:
            with open(full_path, "r", errors="replace") as f:
                lines = f.readlines()
        except (OSError, IOError):
            continue

        for i, line in enumerate(lines, 1):
            m = _DEBT_RE.search(line)
            if m:
                files_with_debt.add(rel_path)
                items.append({
                    "file": rel_path,
                    "line": i,
                    "type": m.group(1).upper(),
                    "text": m.group(2).strip()[:120] if m.group(2) else "",
                    "blame_author": None,
                    "blame_date": None,
                })

    blame_files = sorted(files_with_debt)[:BLAME_CAP]
    capped = len(files_with_debt) > BLAME_CAP

    blame_lookup: dict[str, dict[int, tuple[str, str]]] = {}
    for rel_path in blame_files:
        blame_out = run_git(
            repo, "blame", "--porcelain", rel_path,
            allow_fail=True,
        )
        if not blame_out:
            continue
        file_blame: dict[int, tuple[str, str]] = {}
        current_author = ""
        current_date = ""
        current_line = 0
        for bline in blame_out.splitlines():
            m = re.match(r"^[a-f0-9]{40}\s+\d+\s+(\d+)", bline)
            if m:
                current_line = int(m.group(1))
                continue
            if bline.startswith("author "):
                current_author = bline[7:].strip()
            elif bline.startswith("author-time "):
                try:
                    ts = int(bline[12:].strip())
                    current_date = datetime.fromtimestamp(
                        ts, tz=timezone.utc
                    ).strftime("%Y-%m-%d")
                except (ValueError, OSError):
                    current_date = ""
            elif bline.startswith("\t"):
                if current_line > 0:
                    file_blame[current_line] = (current_author, current_date)

        blame_lookup[rel_path] = file_blame

    for item in items:
        bl = blame_lookup.get(item["file"], {})
        info = bl.get(item["line"])
        if info:
            item["blame_author"] = info[0]
            item["blame_date"] = info[1]

    return {
        "total_count": len(items),
        "items": items,
        "files_with_debt": len(files_with_debt),
        "capped": capped,
    }


# ═══════════════════════════════════════════════════════════════
# SECTION 7: DEV PATTERNS
# ═══════════════════════════════════════════════════════════════

def analyze_dev_patterns(
    commits: list[Commit],
    source_files: list[str],
    repo: str,
    src_dir: str,
    fix_candidates: list[dict],
    bulk_import_sha: str | None,
) -> dict:
    non_merge = [c for c in commits if not c.is_merge]
    source_commits = [c for c in non_merge if c.source_files]
    analysis_commits = source_commits
    if bulk_import_sha:
        analysis_commits = [
            c for c in source_commits
            if c.short_sha != bulk_import_sha
        ]

    if source_commits:
        with_tests = sum(1 for c in source_commits if c.test_files)
        test_co_change = with_tests / len(source_commits)
    else:
        test_co_change = 0.0

    fix_without_test = None
    if fix_candidates:
        no_test = sum(1 for f in fix_candidates if not f["test_changed"])
        fix_without_test = no_test / len(fix_candidates)

    if analysis_commits:
        avg_size = sum(c.source_churn for c in analysis_commits) / len(analysis_commits)
    else:
        avg_size = 0.0
    size_note = "excluding bulk import" if bulk_import_sha and len(analysis_commits) != len(source_commits) else None

    author_lines: dict[str, int] = {}
    for c in source_commits:
        added = sum(f.added for f in c.source_files)
        author_lines[c.author] = author_lines.get(c.author, 0) + added

    total_lines = sum(author_lines.values())
    breakdown = []
    if total_lines > 0:
        for author, lines in sorted(
            author_lines.items(), key=lambda x: x[1], reverse=True
        ):
            breakdown.append({
                "author": author,
                "lines_added": lines,
                "pct": round(lines / total_lines, 3),
            })

    top_contributor = breakdown[0]["author"] if breakdown else "unknown"
    single_dev_pct = breakdown[0]["pct"] if breakdown else 0.0

    return {
        "test_co_change_rate": round(test_co_change, 3),
        "fix_without_test_rate": round(fix_without_test, 3) if fix_without_test is not None else None,
        "avg_commit_size": round(avg_size, 1),
        "avg_commit_size_note": size_note,
        "single_developer_pct": round(single_dev_pct, 3),
        "top_contributor": top_contributor,
        "contributor_breakdown": breakdown[:10],
    }


# ═══════════════════════════════════════════════════════════════
# UTILITY
# ═══════════════════════════════════════════════════════════════

def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            result.append(item)
            seen.add(item)
    return result


def detect_src_dir(repo: str) -> str:
    """Auto-detect source dir: Anchor programs/ → src/ fallback."""
    if os.path.isdir(os.path.join(repo, "programs")):
        return "programs/"
    for candidate in ["src/", "program/", "."]:
        if os.path.isdir(os.path.join(repo, candidate)):
            return candidate
    return "programs/"


# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Git history security analysis for Rust/Solana/Anchor repositories",
    )
    parser.add_argument("--repo", default=".", help="Path to git repository")
    parser.add_argument("--json", default=None, help="Output JSON to file (default: stdout)")
    parser.add_argument("--days", type=int, default=30, help="Late change window (days)")
    parser.add_argument("--limit", type=int, default=10, help="Max fix candidates")
    parser.add_argument("--src-dir", default=None, help="Source directory (auto-detected)")
    args = parser.parse_args()

    repo = os.path.abspath(args.repo)
    src_dir = args.src_dir or detect_src_dir(repo)
    if not src_dir.endswith("/"):
        src_dir += "/"

    t0 = time.monotonic()

    try:
        head = run_git(repo, "rev-parse", "--short", "HEAD").strip()
    except subprocess.CalledProcessError:
        err = {"error": f"{repo} is not a git repository"}
        _write_output(err, args.json)
        return 2

    try:
        branch = run_git(repo, "rev-parse", "--abbrev-ref", "HEAD").strip()
    except subprocess.CalledProcessError:
        branch = "unknown"

    commits = parse_git_log(repo, src_dir)
    source_files = find_source_files(repo, src_dir)
    repo_shape = analyze_repo_shape(commits, src_dir)

    file_areas_cache = _build_file_areas_cache(repo, src_dir)

    fix_cands = find_fix_candidates(
        commits, src_dir, repo, args.limit, file_areas_cache,
    )
    dangerous = analyze_dangerous_areas(
        commits, src_dir, repo, file_areas_cache,
    )
    late = analyze_late_changes(commits, src_dir, args.days)
    forked = analyze_forked_deps(repo)
    debt = find_tech_debt(source_files, repo)
    patterns = analyze_dev_patterns(
        commits, source_files, repo, src_dir,
        fix_cands, repo_shape.get("bulk_import_sha"),
    )

    elapsed_ms = int((time.monotonic() - t0) * 1000)

    result = {
        "meta": {
            "repo": repo,
            "src_dir": src_dir.rstrip("/"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "git_head": head,
            "git_branch": branch,
            "total_commits": len(commits),
            "total_source_files": len(source_files),
            "analysis_time_ms": elapsed_ms,
        },
        "repo_shape": repo_shape,
        "fix_candidates": fix_cands,
        "dangerous_area_changes": dangerous,
        "late_changes": late,
        "forked_deps": forked,
        "tech_debt": debt,
        "dev_patterns": patterns,
    }

    _write_output(result, args.json)
    return 0


def _write_output(data: dict, filepath: str | None) -> None:
    text = json.dumps(data, indent=2)
    if filepath:
        with open(filepath, "w") as f:
            f.write(text)
            f.write("\n")
    else:
        print(text)


if __name__ == "__main__":
    raise SystemExit(main())
