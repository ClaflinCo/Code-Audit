# codeaudit

A polyglot codebase auditor for AI-assisted development. It answers one
question: **have I built a robust, enterprise-grade application, or a
vibe-coded shell?**

It orchestrates battle-tested open-source scanners across four dimensions,
normalizes their output into a single schema, scores each category, and
renders a self-contained HTML dashboard. It also runs AI-aware heuristics
that catch the patterns coding agents tend to produce.

## What it checks

| Category | Tool(s) | Catches |
|---|---|---|
| **Security** | semgrep, gitleaks, built-in heuristics | injection, XSS, hardcoded secrets, disabled TLS, `eval`/`exec` |
| **Redundancy** | jscpd, heuristics | copy-pasted blocks, duplicate logic across files |
| **Tests & correctness** | coverage + heuristics | low test ratio, swallowed exceptions, untested code |
| **Dependencies** | osv-scanner | known CVEs across npm/PyPI/Go/Cargo/Maven |

Every scanner degrades gracefully: a missing tool is reported in the
dashboard and skipped, never fatal. The built-in heuristics need **zero**
external tools, so the auditor always produces useful output.

## Install

```bash
# core (always works)
python3 src/audit.py <path> --out report.html

# full coverage — install the scanners:
pip install semgrep
npm i -g jscpd
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
# gitleaks: https://github.com/gitleaks/gitleaks#installing
```

## Usage

```bash
python3 src/audit.py /path/to/your/repo --out report.html --json report.json
open report.html
```

## Scoring

Each category starts at 100. Findings subtract weighted points by severity
(critical −25, high −12, medium −5, low −2). The overall score averages the
four categories. **Verdict rules:**

- any **critical** finding (secret, active CVE) or overall < 50 → *vibe-coded shell*
- more than 3 highs, or overall < 70 → *functional but hardening required*
- overall < 85 → *near enterprise-grade*
- otherwise → *enterprise-grade*

This is deliberately strict: one leaked credential should fail the audit no
matter how clean the rest of the code is.

## CI integration

```yaml
# .github/workflows/audit.yml
- run: pip install semgrep && npm i -g jscpd
- run: python3 src/audit.py . --json report.json --out report.html
- uses: actions/upload-artifact@v4
  with: { name: codeaudit-report, path: report.html }
```

To **fail the build** on critical findings, read `report.json` and exit
non-zero when `summary.counts.*.critical > 0`.

## Extending it

Add a scanner by registering a function in `src/scanners.py`:

```python
@scanner("my-tool")
def scan_mytool(target, result):
    if not have("my-tool"):
        result.tool_status["my-tool"] = "missing"; return
    # run it, parse output, append Finding(...) objects
```

The dashboard and scoring pick it up automatically — no other changes needed.

## Limitations & honest caveats

- Heuristics are pattern-based and will produce some false positives/negatives.
  The real scanners (semgrep, osv) do the heavy lifting; install them.
- Test-coverage detection here is a file-ratio heuristic. For true line
  coverage, wire in your language's coverage tool (pytest-cov, c8, go test -cover)
  and parse its output into a `TESTS` finding.
- "Functions correctly" can't be fully proven by static analysis — that's what
  your test suite is for. This tool measures whether the *scaffolding* of a
  robust app is present, not runtime behavior.
"# Code-Audit" 
