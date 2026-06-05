"""
Scanner implementations. Each is registered via @scanner and writes Findings
into the shared ScanResult. All are best-effort: a missing binary is recorded
in tool_status and skipped, never fatal.

External tools (install for full coverage):
  semgrep      pip install semgrep
  gitleaks     brew/go install
  osv-scanner  go install github.com/google/osv-scanner/cmd/osv-scanner@latest
  jscpd        npm i -g jscpd
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from core import (
    scanner, have, run_cmd, Finding, Severity, Category, ScanResult,
)

_SEV_MAP = {
    "ERROR": Severity.HIGH, "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
    "WARNING": Severity.MEDIUM, "MEDIUM": Severity.MEDIUM,
    "INFO": Severity.LOW, "LOW": Severity.LOW, "MODERATE": Severity.MEDIUM,
}


# ---- SECURITY: semgrep -------------------------------------------------------

@scanner("semgrep")
def scan_semgrep(target: Path, result: ScanResult) -> None:
    if not have("semgrep"):
        result.tool_status["semgrep"] = "missing"
        return
    rc, out, err = run_cmd(
        ["semgrep", "--config", "auto", "--json", "--quiet", "."], target
    )
    if rc < 0 or not out:
        result.tool_status["semgrep"] = "error"
        return
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        result.tool_status["semgrep"] = "error"
        return
    result.tool_status["semgrep"] = "ok"
    for r in data.get("results", []):
        sev = _SEV_MAP.get(r.get("extra", {}).get("severity", "WARNING"), Severity.MEDIUM)
        result.findings.append(Finding(
            category=Category.SECURITY, severity=sev,
            title=r.get("check_id", "semgrep finding").split(".")[-1],
            detail=r.get("extra", {}).get("message", "")[:400],
            file=r.get("path"), line=r.get("start", {}).get("line"),
            rule_id=r.get("check_id"), tool="semgrep",
            remediation=r.get("extra", {}).get("fix"),
        ))


# ---- SECURITY: secrets (gitleaks) -------------------------------------------

@scanner("gitleaks")
def scan_gitleaks(target: Path, result: ScanResult) -> None:
    if not have("gitleaks"):
        result.tool_status["gitleaks"] = "missing"
        return
    report = target / ".gitleaks-report.json"
    run_cmd(["gitleaks", "detect", "--no-banner", "--report-format", "json",
             "--report-path", str(report), "-s", "."], target)
    if not report.exists():
        result.tool_status["gitleaks"] = "ok"  # ran, no leaks
        return
    try:
        leaks = json.loads(report.read_text() or "[]")
    finally:
        report.unlink(missing_ok=True)
    result.tool_status["gitleaks"] = "ok"
    for lk in leaks:
        result.findings.append(Finding(
            category=Category.SECURITY, severity=Severity.CRITICAL,
            title=f"Hardcoded secret: {lk.get('RuleID', 'secret')}",
            detail=f"Secret matched in {lk.get('File')}",
            file=lk.get("File"), line=lk.get("StartLine"),
            rule_id=lk.get("RuleID"), tool="gitleaks",
            remediation="Rotate the credential and move it to a secret manager / env var.",
        ))


# ---- DEPENDENCIES: osv-scanner ----------------------------------------------

@scanner("osv-scanner")
def scan_osv(target: Path, result: ScanResult) -> None:
    if not have("osv-scanner"):
        result.tool_status["osv-scanner"] = "missing"
        return
    rc, out, err = run_cmd(
        ["osv-scanner", "--format", "json", "-r", "."], target
    )
    if not out:
        result.tool_status["osv-scanner"] = "ok"
        return
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        result.tool_status["osv-scanner"] = "error"
        return
    result.tool_status["osv-scanner"] = "ok"
    for res in data.get("results", []):
        src = res.get("source", {}).get("path")
        for pkg in res.get("packages", []):
            name = pkg.get("package", {}).get("name")
            ver = pkg.get("package", {}).get("version")
            for v in pkg.get("vulnerabilities", []):
                sev = Severity.HIGH
                for s in v.get("severity", []):
                    score = s.get("score", "")
                    if "CRITICAL" in str(score).upper():
                        sev = Severity.CRITICAL
                result.findings.append(Finding(
                    category=Category.DEPENDENCIES, severity=sev,
                    title=f"{name}@{ver}: {v.get('id')}",
                    detail=(v.get("summary") or "Known vulnerability")[:400],
                    file=src, rule_id=v.get("id"), tool="osv-scanner",
                    remediation="Upgrade to a patched version.",
                ))


# ---- REDUNDANCY: jscpd clone detection --------------------------------------

@scanner("jscpd")
def scan_jscpd(target: Path, result: ScanResult) -> None:
    if not have("jscpd"):
        result.tool_status["jscpd"] = "missing"
        return
    rc, out, err = run_cmd(
        ["jscpd", ".", "--silent", "--reporters", "json",
         "--output", "./.jscpd-report"], target
    )
    rep = target / ".jscpd-report" / "jscpd-report.json"
    if not rep.exists():
        result.tool_status["jscpd"] = "ok"
        return
    try:
        data = json.loads(rep.read_text())
    except json.JSONDecodeError:
        result.tool_status["jscpd"] = "error"
        return
    result.tool_status["jscpd"] = "ok"
    dups = data.get("duplicates", [])
    pct = data.get("statistics", {}).get("total", {}).get("percentage", 0)
    result.stats["clone_percentage"] = pct
    for d in dups[:100]:
        first = d.get("firstFile", {})
        result.findings.append(Finding(
            category=Category.REDUNDANCY,
            severity=Severity.MEDIUM if d.get("lines", 0) > 30 else Severity.LOW,
            title=f"Duplicated block ({d.get('lines')} lines)",
            detail=f"Clone between {first.get('name')} and {d.get('secondFile', {}).get('name')}",
            file=first.get("name"), line=first.get("start"),
            tool="jscpd",
            remediation="Extract shared logic into a single reusable function/module.",
        ))


# ---- AI-AWARE HEURISTICS (no external tool) ---------------------------------

_SECRET_INLINE = re.compile(
    r"""(?i)(api[_-]?key|secret|password|token|passwd|aws_access)\s*[:=]\s*['"][^'"]{8,}['"]"""
)
_DANGEROUS = {
    "eval(": "Use of eval — code injection risk.",
    "exec(": "Use of exec — code injection risk.",
    "child_process": "Shell execution — validate/escape all inputs.",
    "dangerouslySetInnerHTML": "Raw HTML injection — XSS risk.",
    "verify=False": "TLS verification disabled.",
    "rejectUnauthorized: false": "TLS verification disabled.",
}
_SWALLOWED = re.compile(r"(?s)except\s*:?\s*\n\s*pass|catch\s*\([^)]*\)\s*\{\s*\}")
_CODE_EXT = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".java", ".php", ".rs"}
_TEST_HINT = re.compile(r"(test|spec)", re.I)
_SKIP_DIRS = {"node_modules", ".git", "dist", "build", "vendor", "__pycache__", ".jscpd-report"}


def _iter_code(target: Path):
    for p in target.rglob("*"):
        if p.is_file() and p.suffix in _CODE_EXT:
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            yield p


@scanner("heuristics")
def scan_heuristics(target: Path, result: ScanResult) -> None:
    result.tool_status["heuristics"] = "ok"
    code_files = 0
    test_files = 0
    for p in _iter_code(target):
        code_files += 1
        rel = str(p.relative_to(target))
        if _TEST_HINT.search(rel):
            test_files += 1
        try:
            text = p.read_text(errors="ignore")
        except Exception:  # noqa: BLE001
            continue

        for i, line in enumerate(text.splitlines(), 1):
            if _SECRET_INLINE.search(line):
                result.findings.append(Finding(
                    category=Category.SECURITY, severity=Severity.CRITICAL,
                    title="Possible hardcoded credential", detail=line.strip()[:160],
                    file=rel, line=i, tool="heuristics",
                    remediation="Move to environment variables or a secret manager.",
                ))
            for needle, msg in _DANGEROUS.items():
                if needle in line:
                    result.findings.append(Finding(
                        category=Category.SECURITY, severity=Severity.HIGH,
                        title=f"Dangerous pattern: {needle.rstrip('(')}",
                        detail=msg, file=rel, line=i, tool="heuristics",
                    ))

        if _SWALLOWED.search(text):
            result.findings.append(Finding(
                category=Category.TESTS, severity=Severity.MEDIUM,
                title="Swallowed exception",
                detail="Empty catch/except hides failures — common in AI-generated code.",
                file=rel, tool="heuristics",
                remediation="Log or handle the error explicitly.",
            ))

    # test coverage heuristic
    result.stats["code_files"] = code_files
    result.stats["test_files"] = test_files
    ratio = (test_files / code_files) if code_files else 0
    result.stats["test_file_ratio"] = round(ratio, 3)
    if code_files >= 5 and ratio < 0.1:
        result.findings.append(Finding(
            category=Category.TESTS, severity=Severity.HIGH,
            title="Little or no test coverage",
            detail=f"Only {test_files} test file(s) for {code_files} source files.",
            tool="heuristics",
            remediation="Add unit/integration tests for critical paths.",
        ))
