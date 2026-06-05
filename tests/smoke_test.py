#!/usr/bin/env python3
"""
Smoke test: build a deliberately-flawed sample codebase, audit it, and assert
the scanner catches the planted issues. Runs with zero external tools (the
built-in heuristics alone must catch the critical security problems).

Usage:  python3 tests/smoke_test.py
Exit 0 on success, 1 on failure.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import scanners  # noqa: F401  registers scanners
from core import run_all


SAMPLE = {
    "src/auth.py": '''import sqlite3
API_KEY = "sk_live_abc123def456ghi789jkl"

def login(user, pw):
    conn = sqlite3.connect("app.db")
    q = "SELECT * FROM users WHERE name='" + user + "'"
    return conn.execute(q).fetchone()

def run(cmd):
    eval(cmd)

def risky():
    try:
        do_thing()
    except:
        pass
''',
    "src/api.js": '''const password = "hunter2supersecret";
fetch(url, { rejectUnauthorized: false });
element.dangerouslySetInnerHTML = { __html: userInput };
''',
    "requirements.txt": "flask==0.12.2\nrequests==2.6.0\n",
}


def build_sample(root: Path) -> None:
    for rel, content in SAMPLE.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        target = Path(tmp)
        build_sample(target)
        summary, findings = run_all(target)

    titles = [f["title"].lower() for f in findings]
    failures = []

    def expect(substr: str, label: str):
        if not any(substr in t for t in titles):
            failures.append(f"  MISSING: expected a finding matching '{label}'")

    expect("credential", "hardcoded credential")
    expect("eval", "dangerous eval")
    expect("rejectunauthorized", "disabled TLS")
    expect("dangerouslysetinnerhtml", "XSS / raw HTML")

    if "shell" not in summary["verdict"].lower():
        failures.append(
            f"  WRONG VERDICT: expected 'vibe-coded shell', got '{summary['verdict']}'"
        )

    crit = sum(1 for f in findings if f["severity"] == "critical")
    if crit < 1:
        failures.append("  NO CRITICALS: expected at least one critical finding")

    print(f"Verdict: {summary['verdict']}  (overall {summary['overall']}/100)")
    print(f"Findings: {len(findings)} total, {crit} critical")

    if failures:
        print("\nSMOKE TEST FAILED:")
        print("\n".join(failures))
        return 1

    print("\nSMOKE TEST PASSED — all planted issues detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
