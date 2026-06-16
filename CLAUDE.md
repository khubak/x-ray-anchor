# CLAUDE.md

Instructions for Claude when contributing to this repository.

## What This Repo Is

A single Claude AI skill: **x-ray-anchor** — a pre-audit readiness report generator for Rust / Solana / Anchor programs. A focused, self-contained capability for Claude Code in VS Code and Cursor.

## Structure

```
SKILL.md      # The skill definition (read by Claude Code)
README.md     # Human-facing overview
VERSION       # Bumped automatically on merge via CI
references/   # solana-vulns.md, threats.md, templates.md
scripts/      # enumerate.sh, analyze_git_security.py, generate_svg.py
CLAUDE.md     # This file (read by Claude Code)
```

## Rules

- One skill, one purpose.
- No fabricated examples - outputs must reflect real model responses.
- No secrets, API keys, or personal data.
