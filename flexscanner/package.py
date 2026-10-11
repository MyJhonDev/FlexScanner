from __future__ import annotations

import re
import shutil
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .models import CoverageItem, Finding
from .rules import Rules
from .util import run_cmd, sha256_file

SAO_PAULO_TZ = "America/Sao_Paulo"


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


def _device_timezone() -> str | None:
    rc, output = run_cmd(["getprop", "persist.sys.timezone"])
    value = output.strip() if rc == 0 else ""
    return value or None


def _to_sao_paulo(raw: str | None, source_timezone: str | None) -> str | None:
    if not raw:
        return None

    raw = raw.strip()
    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S %Z",
    )

    parsed = None
    for fmt in formats:
        try:
            parsed = datetime.strptime(raw, fmt)
            break
        except ValueError:
            continue

    if parsed is None:
        return raw

    try:
        source = ZoneInfo(source_timezone) if source_timezone else ZoneInfo(SAO_PAULO_TZ)
    except ZoneInfoNotFoundError:
        source = ZoneInfo(SAO_PAULO_TZ)

    target = ZoneInfo(SAO_PAULO_TZ)
    localized = parsed.replace(tzinfo=source).astimezone(target)
    return localized.strftime("%d/%m/%Y às %H:%M:%S")


def _query_package_metadata(package: str) -> dict:
    rc, output = run_cmd(["dumpsys", "package", package], timeout=18)
    result = {
        "version_name": None,
        "version_code": None,
        "first_install_time_raw": None,
        "last_update_time_raw": None,
        "first_install_time_sp": None,
        "last_update_time_sp": None,
        "device_timezone": _device_timezone(),
    }
    if rc != 0:
        return result

    name = re.search(r"versionName=([^\s]+)", output)
    code = re.search(r"versionCode=(\d+)", output)
    first = re.search(r"firstInstallTime=([^\n\r]+)", output)
    updated = re.search(r"lastUpdateTime=([^\n\r]+)", output)

    if name:
        result["version_name"] = name.group(1)
    if code:
        result["version_code"] = code.group(1)
    if first:
        result["first_install_time_raw"] = first.group(1).strip()
    if updated:
        result["last_update_time_raw"] = updated.group(1).strip()

    result["first_install_time_sp"] = _to_sao_paulo(
        result["first_install_time_raw"], result["device_timezone"]
    )
    result["last_update_time_sp"] = _to_sao_paulo(
        result["last_update_time_raw"], result["device_timezone"]
    )
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
    metadata = _query_package_metadata(package)
    installed = bool(apk_paths or installer_raw or metadata.get("version_name") or metadata.get("first_install_time_raw"))

    result = {
        "package": package,
        "installed": installed,
        "installer": installer,
        "apk_paths": apk_paths,
        "apk_sha256": {},
        "certificates": {},
        **metadata,
    }

    if not installed:
        coverage.append(
            CoverageItem(
                name="Pacote do Roblox",
                path=package,
                status="not-detected",
                detail="O pacote configurado do Roblox não foi encontrado pelo gerenciador de pacotes do Android.",
            )
        )
        return findings, coverage, result

    coverage.append(
        CoverageItem(
            name="Pacote do Roblox",
            path=package,
            status="detected",
            detail="O gerenciador de pacotes do Android detectou o pacote configurado do Roblox.",
        )
    )

    if installer is None:
        findings.append(
            Finding(
                risk="LOW",
                score=8,
                category="Integridade do Roblox",
                title="Instalador do Roblox não identificado",
                path=package,
                detail="O Android não informou qual aplicativo instalou o Roblox. Esse resultado é inconclusivo.",
            )
        )
    elif installer.lower() not in rules.trusted_installers:
        findings.append(
            Finding(
                risk="MEDIUM",
                score=22,
                category="Integridade do Roblox",
                title="Instalador inesperado",
                path=package,
                detail=f"Instalador informado pelo Android: {installer}. Instalação externa, sozinha, não prova modificação.",
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
                        category="Integridade do Roblox",
                        title="Certificado de assinatura do APK diferente do esperado",
                        path=raw,
                        detail="O certificado encontrado no APK não corresponde aos certificados confiáveis configurados para o Roblox.",
                        evidence=sorted(certs),
                    )
                )
        except (OSError, PermissionError):
            continue

    if apk_paths and readable_apks == 0:
        coverage.append(
            CoverageItem(
                name="APK e certificado do Roblox",
                path="; ".join(apk_paths),
                status="not-verified",
                detail="O caminho do APK foi encontrado, mas o Termux não conseguiu ler o arquivo. A checagem de hash e certificado ficou inconclusiva.",
            )
        )
    elif readable_apks:
        coverage.append(
            CoverageItem(
                name="APK e certificado do Roblox",
                path="; ".join(apk_paths),
                status="readable",
                detail="Os APKs acessíveis tiveram o hash calculado e o certificado foi verificado com apksigner.",
            )
        )

    return findings, coverage, result
