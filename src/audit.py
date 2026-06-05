#!/usr/bin/env python3
"""
codeaudit — entry point.

Usage:
    python src/audit.py <path-to-codebase> [--out report.html] [--json report.json]

Produces a single self-contained HTML dashboard you can open in any browser
or publish as a CI artifact.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import scanners  # noqa: F401  (registers all scanners via import side-effect)
from core import run_all
from dashboard import render_html


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit a codebase for security, redundancy, tests, and dependency health.")
    ap.add_argument("path", help="Path to the codebase root")
    ap.add_argument("--out", default="codeaudit-report.html", help="HTML output path")
    ap.add_argument("--json", dest="json_out", default=None, help="Optional JSON output path")
    args = ap.parse_args()

    target = Path(args.path).resolve()
    if not target.exists():
        print(f"error: {target} does not exist", file=sys.stderr)
        return 2

    print(f"Auditing {target} ...", file=sys.stderr)
    summary, findings = run_all(target)

    if args.json_out:
        Path(args.json_out).write_text(json.dumps({"summary": summary, "findings": findings}, indent=2))
        print(f"JSON written to {args.json_out}", file=sys.stderr)

    Path(args.out).write_text(render_html(target.name, summary, findings))
    print(f"Dashboard written to {args.out}", file=sys.stderr)
    print(f"\nOverall: {summary['overall']}/100  —  {summary['verdict']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
