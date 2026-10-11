from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path

from .models import CoverageItem, Finding


RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


STATUS_LABELS = {
    "readable": "VERIFICADO",
    "detected": "DETECTADO",
    "not-detected": "NÃO DETECTADO",
    "not-verified": "NÃO VERIFICADO",
    "partial": "PARCIAL",
    "unavailable": "INDISPONÍVEL",
    "unexpected": "INESPERADO",
    "empty-or-blocked": "VAZIO OU BLOQUEADO",
    "permission-denied": "ACESSO NEGADO",
    "not-found-or-blocked": "NÃO ENCONTRADO OU BLOQUEADO",
    "not-a-directory": "CAMINHO INVÁLIDO",
    "os-error": "ERRO DO SISTEMA",
}


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

    cert_mismatch = any(
        f.title in {
            "APK signing certificate mismatch",
            "Certificado de assinatura do APK diferente do esperado",
        }
        for f in high
    )
    strong_categories = {f.category for f in high}

    if cert_mismatch or (len(high) >= 2 and len(strong_categories) >= 2):
        code = "STRONG_EVIDENCE_REVIEW_FOR_BAN"
        headline = "Evidências fortes encontradas"
        action = (
            "Foram encontrados sinais fortes em mais de uma categoria. "
            "Confirme os itens de Alto Risco; se baterem com as regras da cup, o caso tem base para ban."
        )
    elif high or len(medium) >= 2 or total_score >= 45:
        code = "INVESTIGATE_FURTHER"
        headline = "Há indícios que precisam de confirmação"
        action = (
            "Revise os arquivos, caminhos e evidências marcados. "
            "Ainda falta confirmação para fechar o caso."
        )
    else:
        code = "NO_STRONG_EVIDENCE"
        headline = "Nenhuma evidência forte encontrada"
        action = (
            "Não foram encontrados indícios fortes nesta varredura. "
            "Use o relatório junto de outras provas, se existirem."
        )

    if inaccessible:
        action += (
            " Algumas áreas do Android não puderam ser verificadas completamente, "
            "então o resultado não garante que o aparelho esteja totalmente limpo."
        )

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
        "timestamp_sao_paulo": datetime.now(ZoneInfo("America/Sao_Paulo")).strftime("%d/%m/%Y às %H:%M:%S"),
        "mode": "somente-leitura",
        "privacy": "O FlexScanner não envia o conteúdo dos arquivos analisados.",
        "limitations": [
            "Arquivos realmente apagados não podem ser recuperados de forma confiável sem acesso forense privilegiado ao armazenamento.",
            "O Android pode bloquear Android/data, Android/obb e os próprios arquivos APK.",
            "Um arquivo Lua ou uma instalação externa, isoladamente, não prova uso de cheat.",
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
    path.write_text(render_text(report, use_color=False), encoding="utf-8")


def render_text(report: dict, use_color: bool = False) -> str:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for finding in report["findings"]:
        grouped[finding["risk"]].append(finding)

    verdict = report["verdict"]
    width = 72
    lines: list[str] = []

    RESET = "\033[0m" if use_color else ""
    BOLD = "\033[1m" if use_color else ""
    DIM = "\033[2m" if use_color else ""
    RED = "\033[91m" if use_color else ""
    YELLOW = "\033[93m" if use_color else ""
    BLUE = "\033[94m" if use_color else ""
    GREEN = "\033[92m" if use_color else ""
    CYAN = "\033[96m" if use_color else ""

    def visible_len(text: str) -> int:
        # Só usado para títulos simples sem ANSI no conteúdo calculado.
        import re
        return len(re.sub(r"\x1b\[[0-9;]*m", "", text))

    def line(char: str = "─") -> None:
        lines.append(DIM + (char * width) + RESET)

    def section(title: str, color: str = "") -> None:
        lines.append("")
        lines.append(f"{color}{BOLD}{title}{RESET}")
        line()

    def item_block(index: int, finding: dict, color: str) -> None:
        title = f"{index:02d}. {finding['title']}"
        lines.append(f"{color}{BOLD}{title}{RESET}")
        lines.append(f"    Categoria : {finding['category']}")
        if finding.get("path"):
            lines.append(f"    Caminho   : {finding['path']}")
        if finding.get("detail"):
            lines.append(f"    Detalhe   : {finding['detail']}")
        if finding.get("evidence"):
            lines.append(f"    Evidências: {', '.join(finding['evidence'])}")
        lines.append("")

    package_info = report.get("roblox_package", {})
    android_dirs = report.get("android_app_dirs", {})

    lines.append(f"{CYAN}{BOLD}FLEXSCANNER{RESET}")
    lines.append(f"{DIM}Scanner de integridade para Roblox no Android{RESET}")
    line()
    lines.append(f"Versão       : {report['version']}")
    lines.append(f"Varredura    : {report.get('timestamp_sao_paulo', 'indisponível')} (São Paulo)")
    lines.append(
        "Achados      : "
        f"{RED}{verdict['high_count']} alto{RESET} | "
        f"{YELLOW}{verdict['medium_count']} médio{RESET} | "
        f"{BLUE}{verdict['low_count']} baixo{RESET}"
    )
    if verdict["coverage_warnings"]:
        lines.append(f"Avisos       : {verdict['coverage_warnings']} área(s) não verificada(s) por completo")

    section("INFORMAÇÕES DO ROBLOX", CYAN)
    installed = package_info.get("installed")
    lines.append(f"Roblox instalado : {'SIM' if installed else 'NÃO'}")
    lines.append(f"Pacote            : {package_info.get('package') or 'indisponível'}")
    if installed:
        lines.append(f"Versão            : {package_info.get('version_name') or 'indisponível'}")
        lines.append(f"Instalado em      : {package_info.get('first_install_time_sp') or 'indisponível'}")
        lines.append(f"Última atualização: {package_info.get('last_update_time_sp') or 'indisponível'}")

        source_code = package_info.get("install_source_code")
        source_label = package_info.get("install_source_label") or "Origem não identificada"
        source_color = GREEN if source_code == "play-store" else YELLOW if source_code in {"external", "adb-shell"} else RED
        lines.append(f"Origem            : {source_color}{source_label}{RESET}")
        lines.append(f"Instalador        : {package_info.get('installer') or 'não identificado'}")
        if package_info.get("initiating_package") and package_info.get("initiating_package") != package_info.get("installer"):
            lines.append(f"Instalação iniciada por: {package_info.get('initiating_package')}")
        if package_info.get("originating_package"):
            lines.append(f"Arquivo/origem    : {package_info.get('originating_package')}")

        sig = package_info.get("signature_status")
        comparison = package_info.get("official_signature_comparison")
        if comparison == "mismatch":
            lines.append(f"Integridade APK   : {RED}{BOLD}ASSINATURA DIFERENTE DA OFICIAL{RESET}")
        elif comparison == "match":
            lines.append(f"Integridade APK   : {GREEN}ASSINATURA OFICIAL CONFIRMADA{RESET}")
        elif sig == "valid":
            lines.append(f"Integridade APK   : assinatura válida; comparação oficial não configurada")
        else:
            lines.append(f"Integridade APK   : não verificada")

    for key, label in (("Android/data", "Pasta data"), ("Android/obb", "Pasta OBB")):
        info = android_dirs.get(key, {})
        status_raw = info.get("status", "unknown")
        exists_text = "ACESSÍVEL" if status_raw in {"readable", "empty-or-blocked"} else "NÃO VERIFICADA"
        lines.append("")
        lines.append(f"{label:17}: {exists_text}")
        if info.get("created_sp"):
            lines.append(f"  Criada em        : {info['created_sp']}")
        else:
            lines.append("  Criada em        : indisponível pelo sistema de arquivos")
        if info.get("modified_sp"):
            lines.append(f"  Última alteração : {info['modified_sp']}")
        if info.get("files_seen") is not None:
            lines.append(f"  Arquivos vistos  : {info.get('files_seen', 0)}")

    risk_sections = (
        ("HIGH", "ALTO RISCO", RED),
        ("MEDIUM", "MÉDIO RISCO", YELLOW),
        ("LOW", "BAIXO RISCO", BLUE),
    )

    for risk, label, color in risk_sections:
        findings = grouped[risk]
        section(f"{label}  ({len(findings)})", color)
        if not findings:
            lines.append(f"{DIM}Nenhum item encontrado nesta categoria.{RESET}")
            continue
        for idx, finding in enumerate(findings, 1):
            item_block(idx, finding, color)

    section("COBERTURA DA VARREDURA", CYAN)
    if not report["coverage"]:
        lines.append(f"{DIM}Nenhuma informação de cobertura disponível.{RESET}")
    else:
        for item in report["coverage"]:
            status_raw = item["status"]
            status = STATUS_LABELS.get(status_raw, status_raw.upper())
            status_color = (
                GREEN if status_raw in {"readable", "detected"}
                else YELLOW if status_raw in {"partial", "empty-or-blocked", "not-detected"}
                else RED
            )
            lines.append(f"{status_color}{BOLD}[{status}]{RESET} {item['name']}")
            lines.append(f"    Caminho: {item['path']}")
            if item.get("detail"):
                lines.append(f"    Detalhe: {item['detail']}")
            lines.append("")

    section("VEREDITO FINAL", CYAN)

    if verdict["code"] == "STRONG_EVIDENCE_REVIEW_FOR_BAN":
        verdict_color = RED
        decision = "CASO FORTE PARA REVISÃO DE BAN"
    elif verdict["code"] == "INVESTIGATE_FURTHER":
        verdict_color = YELLOW
        decision = "INVESTIGAR ANTES DE DECIDIR"
    else:
        verdict_color = GREEN
        decision = "SEM BASE FORTE PARA BAN"

    lines.append(f"{verdict_color}{BOLD}{decision}{RESET}")
    lines.append(f"Status        : {verdict['headline']}")
    lines.append("")
    lines.append(f"{BOLD}Próximo passo{RESET}")
    lines.append(verdict["action"])
    lines.append("")
    lines.append(f"{DIM}Use os achados junto das regras da cup e das demais provas do caso.{RESET}")
    line()

    return "\n".join(lines) + "\n"
