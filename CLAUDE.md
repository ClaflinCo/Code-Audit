# CLAUDE.md — context for Claude Code

This file orients Claude Code when working in this repository.

## What this is

`codeaudit` is a polyglot codebase auditor for AI-assisted development. It
answers one question: **is this a robust, enterprise-grade application or a
vibe-coded shell?** It orchestrates open-source scanners across four
dimensions, normalizes their output into one schema, scores each category,
and renders a self-contained HTML dashboard.

## Architecture (read before editing)

```
src/core.py       Orchestrator. Finding schema, scanner registry (@scanner
                  decorator), severity weights, scoring, verdict logic.
src/scanners.py   One function per scanner. Each wraps a real tool, parses
                  its native output, appends Finding objects. Missing tools
                  degrade gracefully (recorded in tool_status, never fatal).
                  Also contains AI-aware heuristics that need NO external tool.
src/dashboard.py  Renders summary + findings into one self-contained HTML file
                  (inline CSS/JS, no external resources). Has score gauges,
                  category breakdown, filterable findings table.
src/audit.py      CLI entry point. Wires scanners -> scoring -> dashboard.
```

Data flow: `run_all()` in core.py iterates the scanner registry, each scanner
appends `Finding` objects, then `score()` produces per-category 0-100 grades
and an overall verdict.

## Key conventions

- **Adding a scanner:** register with `@scanner("name")` in scanners.py. Guard
  with `if not have("tool"): result.tool_status["tool"]="missing"; return`.
  Parse output, append `Finding(...)`. The dashboard and scoring pick it up
  automatically — no other files change.
- **Severities:** critical/high/medium/low/info with weights 25/12/5/2/0.
  A single critical finding caps the verdict at "vibe-coded shell" by design.
- **Graceful degradation is a hard requirement.** Never let a missing binary
  or a parse error crash the run. The heuristics scanner must always produce
  output with zero external tools installed.
- Core tool uses **stdlib only**. External scanners are optional enhancements.

## Setup

```bash
bash bootstrap.sh                 # installs semgrep, jscpd, osv-scanner where possible
python3 src/audit.py <path> --out report.html --json report.json
```

## How to verify changes

There is a smoke test that builds a deliberately-flawed sample repo and
asserts the scanner catches the planted issues:

```bash
python3 tests/smoke_test.py
```

It should report a "vibe-coded shell" verdict and find the hardcoded secret,
SQL injection, eval, disabled TLS, and XSS. If those regress, a scanner broke.

## Good next tasks (mentioned but not yet built)

- CI gate: read report.json, exit non-zero when any category's critical count > 0.
- Real line-coverage: parse pytest-cov / c8 / `go test -cover` into TESTS findings
  instead of the current file-ratio heuristic.
- SARIF output for GitHub code-scanning integration.
