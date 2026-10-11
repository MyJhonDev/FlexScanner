from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from .models import CoverageItem, Finding


RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (
            finding.risk,
            finding.category,
            finding.title,
            finding.path,
            tuple(finding.evidence),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result


def calculate_verdict(findings: list[Finding], coverage: list[CoverageItem]) -> dict:
    total_score = sum(f.score for f in findings)
    high = [f for f in findings if f.risk == "HIGH"]
    medium = [f for f in findings if f.risk == "MEDIUM"]
    inaccessible = [c for c in coverage if c.status in {"not-verified", "partial", "unavailable"}]

    # Strong result requires more than one independent strong signal, or one certificate mismatch.
    cert_mismatch = any(f.title == "APK signing certificate mismatch" for f in high)
    strong_categories = {f.category for f in high}

    if cert_mismatch or len(high) >= 2 and len(strong_categories) >= 2:
        code = "STRONG_EVIDENCE_REVIEW_FOR_BAN"
        headline = "Strong evidence detected"
        action = (
            "Human review is required immediately. If the evidence is confirmed under the cup rules, "
            "the account can be treated as ban-eligible. Do not auto-ban from this scanner alone."
        )
    elif high or len(medium) >= 2 or total_score >= 45:
        code = "INVESTIGATE_FURTHER"
        headline = "Further investigation recommended"
        action = "Do not ban automatically. Review the listed paths and evidence before taking action."
    else:
        code = "NO_STRONG_EVIDENCE"
        headline = "No strong evidence detected"
        action = "No direct ban recommendation from this scan. Preserve the report if additional review is needed."

    if inaccessible:
        action += " Some Android areas were not fully verifiable, so the result is not a guarantee of a clean device."

    return {
        "code": code,
        "headline": headline,
        "action": action,
        "score": total_score,
        "high_count": len(high),
        "medium_count": len(medium),
        "low_count": len([f for f in findings if f.risk == "LOW"]),
        "coverage_warnings": len(inaccessible),
    }


def build_report(
    findings: list[Finding],
    coverage: list[CoverageItem],
    storage_stats: dict,
    package_info: dict,
    android_dirs: dict,
    scanner_version: str,
) -> dict:
    findings = dedupe_findings(findings)
    findings.sort(key=lambda f: (RISK_ORDER.get(f.risk, 9), -f.score, f.path))
    verdict = calculate_verdict(findings, coverage)

    return {
        "scanner": "FlexScanner",
        "version": scanner_version,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "read-only-local",
        "privacy": "No file contents are uploaded by this project.",
        "limitations": [
            "Deleted files cannot be reliably recovered or proven absent without privileged/raw-storage forensic access.",
            "Android scoped storage can block Android/data, Android/obb, and APK bytes.",
            "A sideloaded installer or a Lua file alone is not proof of cheating.",
        ],
        "verdict": verdict,
        "coverage": [c.to_dict() for c in coverage],
        "findings": [f.to_dict() for f in findings],
        "storage_stats": storage_stats,
        "roblox_package": package_info,
        "android_app_dirs": android_dirs,
    }


def save_json(report: dict, path: Path) -> None:
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def save_text(report: dict, path: Path) -> None:
    path.write_text(render_text(report), encoding="utf-8")


def render_text(report: dict) -> str:
    lines: list[str] = []
    width = 78

    def rule(char: str = "=") -> None:
        lines.append(char * width)

    rule()
    lines.append("FLEXSCANNER")
    lines.append(f"Version: {report['version']}")
    lines.append(f"UTC: {report['timestamp_utc']}")
    rule()

    grouped: dict[str, list[dict]] = defaultdict(list)
    for finding in report["findings"]:
        grouped[finding["risk"]].append(finding)

    for risk, label in (("HIGH", "HIGH RISK"), ("MEDIUM", "MEDIUM RISK"), ("LOW", "LOW RISK")):
        lines.append("")
        rule("-")
        lines.append(f"{label} | {len(grouped[risk])} finding(s)")
        rule("-")
        if not grouped[risk]:
            lines.append("None detected.")
            continue

        for idx, finding in enumerate(grouped[risk], 1):
            lines.append(f"[{idx}] {finding['title']}")
            lines.append(f"    Category: {finding['category']}")
            lines.append(f"    Score: {finding['score']}")
            if finding.get("path"):
                lines.append(f"    Path: {finding['path']}")
            if finding.get("detail"):
                lines.append(f"    Detail: {finding['detail']}")
            if finding.get("evidence"):
                lines.append("    Evidence: " + ", ".join(finding["evidence"]))
            lines.append("")

    lines.append("")
    rule("-")
    lines.append("SCAN COVERAGE")
    rule("-")
    for item in report["coverage"]:
        lines.append(f"[{item['status'].upper()}] {item['name']}")
        lines.append(f"    Path: {item['path']}")
        if item.get("detail"):
            lines.append(f"    Detail: {item['detail']}")

    verdict = report["verdict"]
    lines.append("")
    rule()
    lines.append("FINAL VERDICT")
    rule()
    lines.append(f"Result: {verdict['headline']}")
    lines.append(f"Code: {verdict['code']}")
    lines.append(f"Risk score: {verdict['score']}")
    lines.append(
        f"Findings: High={verdict['high_count']} | Medium={verdict['medium_count']} | Low={verdict['low_count']}"
    )
    lines.append(f"Coverage warnings: {verdict['coverage_warnings']}")
    lines.append("")
    lines.append("Recommended action:")
    lines.append(verdict["action"])
    lines.append("")
    lines.append("Important: this scanner is an evidence triage tool, not an automatic punishment engine.")
    rule()

    return "\n".join(lines) + "\n"
