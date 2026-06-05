"""
codeaudit — core orchestrator.

Runs language-appropriate scanners, normalizes everything into a single
Finding schema, scores per category, and emits JSON the dashboard consumes.

Design goals:
- Polyglot: tools are chosen because they span many languages.
- Resilient: a missing tool degrades gracefully (skipped, not crashed).
- AI-aware: extra heuristics catch what generic SAST misses in agent code.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import dataclasses
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Callable


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> int:
        return {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}[self.value]


class Category(str, Enum):
    SECURITY = "security"
    REDUNDANCY = "redundancy"
    TESTS = "tests"
    DEPENDENCIES = "dependencies"


@dataclass
class Finding:
    category: Category
    severity: Severity
    title: str
    detail: str
    file: str | None = None
    line: int | None = None
    rule_id: str | None = None
    tool: str | None = None
    remediation: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    tool_status: dict[str, str] = field(default_factory=dict)  # tool -> ok|missing|error
    stats: dict = field(default_factory=dict)


# ---- scanner registry --------------------------------------------------------

ScannerFn = Callable[[Path, "ScanResult"], None]
_SCANNERS: list[tuple[str, ScannerFn]] = []


def scanner(name: str):
    def deco(fn: ScannerFn):
        _SCANNERS.append((name, fn))
        return fn
    return deco


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def run_cmd(args: list[str], cwd: Path, timeout: int = 600) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            args, cwd=str(cwd), capture_output=True, text=True, timeout=timeout
        )
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except Exception as e:  # noqa: BLE001
        return -1, "", str(e)


# ---- scoring -----------------------------------------------------------------

def score(result: ScanResult) -> dict:
    """Per-category 0-100 grade. Start at 100, subtract weighted severities,
    floored at 0. Verdict separates 'enterprise-ready' from 'vibe shell'."""
    cats = {c.value: 100 for c in Category}
    counts = {c.value: {s.value: 0 for s in Severity} for c in Category}

    for f in result.findings:
        cats[f.category.value] = max(0, cats[f.category.value] - f.severity.weight)
        counts[f.category.value][f.severity.value] += 1

    overall = round(sum(cats.values()) / len(cats))
    crit = sum(1 for f in result.findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in result.findings if f.severity == Severity.HIGH)

    if crit > 0 or overall < 50:
        verdict = "Vibe-coded shell — not production-safe"
    elif high > 3 or overall < 70:
        verdict = "Functional but hardening required"
    elif overall < 85:
        verdict = "Near enterprise-grade — minor gaps"
    else:
        verdict = "Enterprise-grade"

    return {
        "overall": overall,
        "categories": cats,
        "counts": counts,
        "verdict": verdict,
        "tool_status": result.tool_status,
        "stats": result.stats,
    }


def run_all(target: Path) -> tuple[dict, list[dict]]:
    result = ScanResult()
    for name, fn in _SCANNERS:
        try:
            fn(target, result)
        except Exception as e:  # noqa: BLE001
            result.tool_status[name] = f"error: {e}"
    return score(result), [f.to_dict() for f in result.findings]
