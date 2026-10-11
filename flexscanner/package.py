from __future__ import annotations

import re
import shutil
from pathlib import Path

from .models import CoverageItem, Finding
from .rules import Rules
from .util import run_cmd, sha256_file


def _query_installer(package: str) -> tuple[str | None, str]:
    commands = [
        ["pm", "list", "packages", "-i", package],
        ["cmd", "package", "list", "packages", "-i", package],
    ]
    for command in commands:
        rc, output = run_cmd(command)
        if rc == 0 and package in output:
            match = re.search(r"installer=([^\s]+)", output)
            return (match.group(1) if match else None), output
    return None, ""


def _query_apk_paths(package: str) -> list[str]:
    for command in (["pm", "path", package], ["cmd", "package", "path", package]):
        rc, output = run_cmd(list(command))
        if rc != 0:
            continue
        paths = []
        for line in output.splitlines():
            if line.startswith("package:"):
                paths.append(line.split("package:", 1)[1].strip())
        if paths:
            return paths
    return []


def _query_version(package: str) -> dict:
    rc, output = run_cmd(["dumpsys", "package", package], timeout=18)
    result = {"version_name": None, "version_code": None}
    if rc != 0:
        return result
    name = re.search(r"versionName=([^\s]+)", output)
    code = re.search(r"versionCode=(\d+)", output)
    if name:
        result["version_name"] = name.group(1)
    if code:
        result["version_code"] = code.group(1)
    return result


def _apksigner_certificate(path: Path) -> dict:
    if shutil.which("apksigner") is None:
        return {"status": "tool-unavailable", "cert_sha256": []}

    rc, output = run_cmd(["apksigner", "verify", "--print-certs", str(path)], timeout=25)
    if rc != 0:
        return {"status": "verification-failed", "cert_sha256": [], "raw": output[:3000]}

    certs = []
    for line in output.splitlines():
        if "certificate SHA-256 digest:" in line:
            digest = line.split("digest:", 1)[1].strip().replace(":", "").lower()
            certs.append(digest)
    return {"status": "verified", "cert_sha256": sorted(set(certs))}


def inspect_roblox_package(rules: Rules) -> tuple[list[Finding], list[CoverageItem], dict]:
    findings: list[Finding] = []
    coverage: list[CoverageItem] = []
    package = rules.roblox_package

    installer, installer_raw = _query_installer(package)
    apk_paths = _query_apk_paths(package)
    version = _query_version(package)
    installed = bool(apk_paths or installer_raw)

    result = {
        "package": package,
        "installed": installed,
        "installer": installer,
        "apk_paths": apk_paths,
        "apk_sha256": {},
        "certificates": {},
        **version,
    }

    if not installed:
        coverage.append(
            CoverageItem(
                name="Roblox package",
                path=package,
                status="not-detected",
                detail="The configured Roblox package was not detected by Package Manager queries.",
            )
        )
        return findings, coverage, result

    coverage.append(
        CoverageItem(
            name="Roblox package",
            path=package,
            status="detected",
            detail="Package Manager detected the configured Roblox package.",
        )
    )

    if installer is None:
        findings.append(
            Finding(
                risk="LOW",
                score=8,
                category="Roblox integrity",
                title="Installer could not be identified",
                path=package,
                detail="Package Manager did not expose an installer identity. This is inconclusive.",
            )
        )
    elif installer.lower() not in rules.trusted_installers:
        findings.append(
            Finding(
                risk="MEDIUM",
                score=22,
                category="Roblox integrity",
                title="Untrusted or unexpected installer",
                path=package,
                detail=f"Installer reported by Android: {installer}. Sideloading alone does not prove modification.",
                evidence=[installer],
            )
        )

    readable_apks = 0
    for raw in apk_paths:
        path = Path(raw)
        try:
            if not path.is_file():
                continue
            with path.open("rb"):
                pass
            readable_apks += 1
            result["apk_sha256"][raw] = sha256_file(path)
            cert_info = _apksigner_certificate(path)
            result["certificates"][raw] = cert_info

            certs = set(cert_info.get("cert_sha256", []))
            expected = rules.official_roblox_cert_sha256
            if expected and certs and not (certs & expected):
                findings.append(
                    Finding(
                        risk="HIGH",
                        score=90,
                        category="Roblox integrity",
                        title="APK signing certificate mismatch",
                        path=raw,
                        detail="APK certificate does not match the configured trusted Roblox certificate allowlist.",
                        evidence=sorted(certs),
                    )
                )
        except (OSError, PermissionError):
            continue

    if apk_paths and readable_apks == 0:
        coverage.append(
            CoverageItem(
                name="Roblox APK bytes/certificate",
                path="; ".join(apk_paths),
                status="not-verified",
                detail="Package paths were found, but Termux could not read the APK bytes. Hash/certificate checks are therefore inconclusive.",
            )
        )
    elif readable_apks:
        coverage.append(
            CoverageItem(
                name="Roblox APK bytes/certificate",
                path="; ".join(apk_paths),
                status="readable",
                detail="Readable APK files were hashed and certificate inspection was attempted with apksigner.",
            )
        )

    return findings, coverage, result
