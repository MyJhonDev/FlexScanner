from __future__ import annotations

import hashlib
import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from .models import CoverageItem, Finding
from .rules import Rules
from .storage import candidate_shared_roots
from .util import safe_realpath, sao_paulo_timezone

SAO_PAULO_TZ = sao_paulo_timezone()
MAX_DELTA_TEXT_BYTES = 8 * 1024 * 1024
MAX_DELTA_FINDINGS_PER_GROUP = 30
URL_RE = re.compile(rb"https?://[^\s\"'<>]+", re.IGNORECASE)
SCRIPT_LOG_RE = re.compile(r"^\s*#\d+\s*:", re.MULTILINE)


def _read_small(path: Path, limit: int = MAX_DELTA_TEXT_BYTES) -> bytes | None:
    try:
        st = path.stat()
        if st.st_size <= 0 or st.st_size > limit:
            return None
        return path.read_bytes()
    except (OSError, PermissionError):
        return None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _format_epoch_sp(value: str | int | None) -> str | None:
    if value is None:
        return None
    try:
        epoch = int(value)
        if epoch <= 0:
            return None
        return datetime.fromtimestamp(epoch, tz=SAO_PAULO_TZ).strftime("%d/%m/%Y às %H:%M:%S")
    except (TypeError, ValueError, OSError, OverflowError):
        return None


def _domains_from_bytes(data: bytes, limit: int = 8) -> list[str]:
    domains: list[str] = []
    seen: set[str] = set()
    for match in URL_RE.findall(data):
        try:
            url = match.decode("utf-8", errors="ignore").rstrip(").,;]")
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            continue
        if host and host not in seen:
            seen.add(host)
            domains.append(host)
        if len(domains) >= limit:
            break
    return domains


def _indicator_hits(data: bytes, rules: Rules) -> list[str]:
    return sorted(name for name, regex in rules.lua_indicators.items() if regex.search(data))


def _game_hits(name: str, data: bytes, rules: Rules) -> list[str]:
    normalized_name = name.lower().replace("_", " ").replace("-", " ")
    text_lower = data[:MAX_DELTA_TEXT_BYTES].lower()
    hits: list[str] = []
    for term in sorted(rules.game_context_terms):
        if term in normalized_name or term.encode() in text_lower:
            hits.append(term)
    return hits


def _find_casefold_child(parent: Path, name: str) -> Path | None:
    try:
        for child in parent.iterdir():
            if child.name.casefold() == name.casefold() and child.is_dir():
                return child
    except (OSError, PermissionError):
        return None
    return None


def find_delta_roots() -> list[Path]:
    bases = candidate_shared_roots()
    termux_storage = Path.home() / "storage"
    if termux_storage.exists() and termux_storage.is_dir():
        bases.append(termux_storage)

    roots: list[Path] = []
    seen: set[str] = set()
    for base in bases:
        try:
            for child in base.iterdir():
                if child.name.casefold() != "delta" or not child.is_dir():
                    continue
                real = safe_realpath(child)
                key = str(real)
                if key in seen:
                    continue
                seen.add(key)
                roots.append(real)
        except (OSError, PermissionError):
            continue
    return roots


def _scan_saved_scripts(delta_root: Path, rules: Rules) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    info = {"directory": None, "saved_count": 0, "analyzed_count": 0}
    scripts_dir = _find_casefold_child(delta_root, "Scripts")
    if not scripts_dir:
        return findings, info

    info["directory"] = str(scripts_dir)
    produced = 0
    try:
        files = [p for p in scripts_dir.rglob("*") if p.is_file()]
    except (OSError, PermissionError):
        return findings, info

    info["saved_count"] = len(files)
    for path in files:
        if produced >= MAX_DELTA_FINDINGS_PER_GROUP:
            break
        data = _read_small(path)
        if data is None:
            continue
        info["analyzed_count"] += 1
        indicators = _indicator_hits(data, rules)
        games = _game_hits(path.name, data, rules)
        domains = _domains_from_bytes(data)

        evidence = ["script salvo em Delta/Scripts"]
        evidence.extend(indicators)
        evidence.extend(games)
        if domains:
            evidence.append("domínios: " + ", ".join(domains[:5]))
        evidence.append("sha256: " + _sha256(data))

        if len(indicators) >= 2 or (games and indicators):
            risk = "HIGH"
            score = 52
            title = "Script salvo no Delta com indicadores de exploit"
            detail = "O arquivo está salvo na pasta Scripts do Delta e contém padrões associados à execução de scripts."
        else:
            risk = "MEDIUM"
            score = 28
            title = "Script salvo na pasta Scripts do Delta"
            detail = "O Delta mantém este arquivo como script salvo, mesmo que ele não use extensão .lua."

        findings.append(
            Finding(
                risk=risk,
                score=score,
                category="Delta Executor",
                title=title,
                path=str(path),
                detail=detail,
                evidence=evidence,
            )
        )
        produced += 1

    return findings, info


def _scan_autoexec(delta_root: Path, rules: Rules) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    info = {"directories": [], "files": 0}
    produced = 0

    try:
        dirs = [p for p in delta_root.rglob("*") if p.is_dir() and p.name.casefold() in {"autoexec", "autoexecute"}]
    except (OSError, PermissionError):
        return findings, info

    for directory in dirs:
        info["directories"].append(str(directory))
        try:
            files = [p for p in directory.rglob("*") if p.is_file()]
        except (OSError, PermissionError):
            files = []
        info["files"] += len(files)

        if not files:
            findings.append(
                Finding(
                    risk="LOW",
                    score=8,
                    category="Delta Executor",
                    title="Pasta de autoexec do Delta encontrada, mas vazia",
                    path=str(directory),
                    detail="A pasta existe, porém nenhum arquivo de execução automática foi encontrado nela.",
                    evidence=[directory.name],
                )
            )
            continue

        for path in files:
            if produced >= MAX_DELTA_FINDINGS_PER_GROUP:
                break
            data = _read_small(path)
            indicators = _indicator_hits(data or b"", rules) if data else []
            evidence = ["arquivo dentro de autoexec/autoexecute"] + indicators
            if data:
                evidence.append("sha256: " + _sha256(data))
            findings.append(
                Finding(
                    risk="HIGH",
                    score=58,
                    category="Execução automática",
                    title="Script configurado em pasta de autoexec do Delta",
                    path=str(path),
                    detail="O arquivo está dentro de uma pasta usada pelo Delta para execução automática.",
                    evidence=evidence,
                )
            )
            produced += 1

    return findings, info


def _scan_crash_logs(delta_root: Path) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    info = {"directory": None, "logs": 0, "execution_logs": 0}
    crashes_dir = _find_casefold_child(delta_root, "Crashes")
    if not crashes_dir:
        return findings, info

    info["directory"] = str(crashes_dir)
    try:
        files = [p for p in crashes_dir.rglob("*") if p.is_file() and p.suffix.lower() in {".txt", ".log"}]
    except (OSError, PermissionError):
        return findings, info
    info["logs"] = len(files)

    for path in files[:MAX_DELTA_FINDINGS_PER_GROUP]:
        data = _read_small(path, 4 * 1024 * 1024)
        if not data:
            continue
        text = data.decode("utf-8", errors="replace")

        ran_match = re.search(r"^\s*Scripts Ran\s*:\s*(true|false)\s*$", text, re.IGNORECASE | re.MULTILINE)
        action_match = re.search(r"^\s*Last Action\s*:\s*(.+?)\s*$", text, re.IGNORECASE | re.MULTILINE)
        game_match = re.search(r"^\s*Game ID\s*:\s*(\d+)\s*$", text, re.IGNORECASE | re.MULTILINE)
        place_match = re.search(r"^\s*Place ID\s*:\s*(\d+)\s*$", text, re.IGNORECASE | re.MULTILINE)
        ts_match = re.search(r"^\s*Timestamp \(Unix\)\s*:\s*(\d+)\s*$", text, re.IGNORECASE | re.MULTILINE)

        scripts_ran = bool(ran_match and ran_match.group(1).lower() == "true")
        action = action_match.group(1).strip() if action_match else ""
        script_section = text
        section_match = re.search(r"Script Log:\s*(.*?)(?:\n\s*Stacktrace:|\Z)", text, re.IGNORECASE | re.DOTALL)
        if section_match:
            script_section = section_match.group(1)
        script_entries = len(SCRIPT_LOG_RE.findall(script_section))
        domains = _domains_from_bytes(script_section.encode("utf-8", errors="ignore"))
        when_sp = _format_epoch_sp(ts_match.group(1) if ts_match else None)

        confirms_execution = scripts_ran and "execute" in action.lower()
        has_trace = script_entries > 0 or b"loadstring" in data.lower() or b"httpget" in data.lower()
        if not confirms_execution and not has_trace:
            continue

        evidence: list[str] = []
        if scripts_ran:
            evidence.append("Scripts Ran: true")
        if action:
            evidence.append("Last Action: " + action[:80])
        if script_entries:
            evidence.append(f"Script Log: {script_entries} entrada(s)")
        if game_match:
            evidence.append("Game ID: " + game_match.group(1))
        if place_match:
            evidence.append("Place ID: " + place_match.group(1))
        if domains:
            evidence.append("domínios: " + ", ".join(domains[:5]))
        evidence.append("sha256: " + _sha256(data))

        if confirms_execution:
            info["execution_logs"] += 1
            title = "Log do Delta confirma execução de script"
            risk = "HIGH"
            score = 75
            detail = "O próprio crash log do Delta registra que scripts foram executados"
            if when_sp:
                detail += f" em {when_sp} (São Paulo)"
            detail += "."
        else:
            title = "Crash log do Delta contém histórico de script"
            risk = "HIGH"
            score = 62
            detail = "O log contém Script Log ou padrões de execução remota associados ao Delta."

        findings.append(
            Finding(
                risk=risk,
                score=score,
                category="Execução confirmada" if confirms_execution else "Delta Executor",
                title=title,
                path=str(path),
                detail=detail,
                evidence=evidence,
            )
        )

    return findings, info


def _scan_workspace(delta_root: Path, rules: Rules) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    info = {"directory": None, "files": 0, "lua_files": 0, "game_related": 0, "capture_indexes": 0}
    workspace = _find_casefold_child(delta_root, "Workspace")
    if not workspace:
        return findings, info
    info["directory"] = str(workspace)

    try:
        files = [p for p in workspace.rglob("*") if p.is_file()]
    except (OSError, PermissionError):
        return findings, info
    info["files"] = len(files)
    info["lua_files"] = sum(1 for p in files if p.suffix.lower() in {".lua", ".luau"})

    interesting: list[str] = []
    for path in files:
        normalized = path.name.lower().replace("_", " ").replace("-", " ")
        if any(term in normalized for term in rules.game_context_terms):
            info["game_related"] += 1
            if len(interesting) < 5:
                interesting.append(path.name)

        if path.name.casefold() == "index.txt" and "kalicapture" in str(path.parent).lower():
            data = _read_small(path, 2 * 1024 * 1024)
            if not data:
                continue
            lower = data.lower()
            if b"httpget" not in lower and b"loadstring" not in lower and b"request" not in lower:
                continue
            info["capture_indexes"] += 1
            domains = _domains_from_bytes(data)
            counts = {
                "httpget": len(re.findall(rb"\|\s*httpget\s*\|", lower)),
                "loadstring": len(re.findall(rb"\|\s*loadstring\s*\|", lower)),
                "request": len(re.findall(rb"\|\s*(?:http_request|request)\s*\|", lower)),
            }
            evidence = [f"httpget: {counts['httpget']}", f"loadstring: {counts['loadstring']}", f"request: {counts['request']}"]
            if domains:
                evidence.append("domínios: " + ", ".join(domains[:5]))
            evidence.append("sha256: " + _sha256(data))
            findings.append(
                Finding(
                    risk="HIGH",
                    score=60,
                    category="Rastros de execução",
                    title="Registro do Workspace contém chamadas capturadas",
                    path=str(path),
                    detail="O índice registra chamadas como HttpGet, loadstring ou request durante uma sessão do Workspace.",
                    evidence=evidence,
                )
            )

    if info["game_related"]:
        findings.append(
            Finding(
                risk="HIGH",
                score=48,
                category="Delta Executor",
                title="Workspace do Delta contém arquivo relacionado ao jogo analisado",
                path=str(workspace),
                detail="Foram encontrados arquivos no Workspace cujo nome corresponde ao contexto de jogo configurado no scanner.",
                evidence=interesting or [f"{info['game_related']} arquivo(s) relacionado(s)"],
            )
        )
    elif info["lua_files"]:
        findings.append(
            Finding(
                risk="MEDIUM",
                score=24,
                category="Delta Executor",
                title="Workspace do Delta contém scripts Lua",
                path=str(workspace),
                detail=f"Foram encontrados {info['lua_files']} arquivo(s) .lua/.luau no Workspace do Delta.",
                evidence=[f"{info['lua_files']} script(s)"],
            )
        )

    return findings, info


def inspect_delta_executor(rules: Rules) -> tuple[list[Finding], list[CoverageItem], dict]:
    findings: list[Finding] = []
    coverage: list[CoverageItem] = []
    info = {
        "detected": False,
        "roots": [],
        "scripts_saved": 0,
        "scripts_analyzed": 0,
        "autoexec_files": 0,
        "crash_logs": 0,
        "execution_logs": 0,
        "workspace_files": 0,
        "workspace_lua_files": 0,
        "workspace_capture_indexes": 0,
    }

    roots = find_delta_roots()
    if not roots:
        coverage.append(
            CoverageItem(
                name="Delta Executor",
                path="~/storage/shared/Delta",
                status="not-detected",
                detail="Nenhuma pasta Delta foi encontrada nas raízes de armazenamento acessíveis.",
            )
        )
        return findings, coverage, info

    info["detected"] = True
    for delta_root in roots:
        info["roots"].append(str(delta_root))
        marker_names = {"internals", "scripts", "workspace", "autoexecute", "crashes"}
        try:
            children = {p.name.casefold() for p in delta_root.iterdir() if p.is_dir()}
        except (OSError, PermissionError):
            children = set()
        markers = sorted(marker_names & children)

        coverage.append(
            CoverageItem(
                name="Delta Executor",
                path=str(delta_root),
                status="detected",
                detail="Pasta Delta encontrada e analisada de forma específica.",
            )
        )

        findings.append(
            Finding(
                risk="HIGH" if len(markers) >= 3 else "MEDIUM",
                score=45 if len(markers) >= 3 else 28,
                category="Delta Executor",
                title="Estrutura do Delta Executor encontrada" if len(markers) >= 3 else "Pasta Delta encontrada",
                path=str(delta_root),
                detail=(
                    "A pasta possui várias subpastas características do Delta Executor."
                    if len(markers) >= 3
                    else "A pasta Delta foi encontrada no armazenamento acessível."
                ),
                evidence=markers or ["Delta"],
            )
        )

        group, scripts = _scan_saved_scripts(delta_root, rules)
        findings.extend(group)
        info["scripts_saved"] += scripts["saved_count"]
        info["scripts_analyzed"] += scripts["analyzed_count"]

        group, autoexec = _scan_autoexec(delta_root, rules)
        findings.extend(group)
        info["autoexec_files"] += autoexec["files"]

        group, crashes = _scan_crash_logs(delta_root)
        findings.extend(group)
        info["crash_logs"] += crashes["logs"]
        info["execution_logs"] += crashes["execution_logs"]

        group, workspace = _scan_workspace(delta_root, rules)
        findings.extend(group)
        info["workspace_files"] += workspace["files"]
        info["workspace_lua_files"] += workspace["lua_files"]
        info["workspace_capture_indexes"] += workspace["capture_indexes"]

    return findings, coverage, info
