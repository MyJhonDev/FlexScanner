from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from .models import CoverageItem, Finding
from .rules import Rules
from .util import safe_realpath

MAX_TEXT_FILE_BYTES = 8 * 1024 * 1024
MAX_FILES_TO_SCAN = 120_000


def candidate_shared_roots() -> list[Path]:
    choices = [
        Path.home() / "storage" / "shared",
        Path("/storage/emulated/0"),
        Path("/sdcard"),
    ]

    roots: list[Path] = []
    seen: set[str] = set()
    for path in choices:
        try:
            if not path.exists() or not path.is_dir():
                continue
            real = safe_realpath(path)
            key = str(real)
            if key in seen:
                continue
            seen.add(key)
            roots.append(real)
        except OSError:
            continue
    return roots


def safe_walk(root: Path) -> Iterable[tuple[str, list[str], list[str]]]:
    def onerror(_exc: OSError) -> None:
        return None

    yield from os.walk(root, topdown=True, onerror=onerror, followlinks=False)


def _is_under_trash(path_parts: tuple[str, ...], rules: Rules) -> bool:
    lowered = {part.lower() for part in path_parts}
    return any(name in lowered for name in rules.trash_directory_names)


def scan_shared_storage(rules: Rules) -> tuple[list[Finding], list[CoverageItem], dict]:
    findings: list[Finding] = []
    coverage: list[CoverageItem] = []
    stats = {
        "roots": [],
        "directories_seen": 0,
        "files_seen": 0,
        "script_candidates_seen": 0,
        "scan_limit_reached": False,
    }

    roots = candidate_shared_roots()
    if not roots:
        coverage.append(
            CoverageItem(
                name="Armazenamento compartilhado",
                path="~/storage/shared",
                status="unavailable",
                detail="O armazenamento compartilhado não pôde ser acessado. Execute termux-setup-storage e permita o acesso aos arquivos.",
            )
        )
        return findings, coverage, stats

    for root in roots:
        stats["roots"].append(str(root))
        coverage.append(
            CoverageItem(
                name="Armazenamento compartilhado",
                path=str(root),
                status="readable",
                detail="Armazenamento acessível analisado sem alterar ou apagar arquivos.",
            )
        )

        for current, dirs, files in safe_walk(root):
            stats["directories_seen"] += 1
            current_path = Path(current)
            under_trash = _is_under_trash(current_path.parts, rules)

            # Do not traverse symlinked directories.
            dirs[:] = [d for d in dirs if not (current_path / d).is_symlink()]

            for directory in dirs:
                lower = directory.lower()
                full = current_path / directory
                executor_hits = rules.match_name_tokens(directory)

                if lower in rules.high_signal_directories:
                    findings.append(
                        Finding(
                            risk="HIGH",
                            score=38,
                            category="Armazenamento",
                            title="Pasta de execução automática suspeita",
                            path=str(full),
                            detail=f"O nome da pasta corresponde a um local comum de execução automática: {directory}",
                            evidence=[directory],
                        )
                    )
                elif executor_hits:
                    findings.append(
                        Finding(
                            risk="MEDIUM",
                            score=28,
                            category="Armazenamento",
                            title="Pasta associada a executor",
                            path=str(full),
                            detail="O nome da pasta corresponde a um executor conhecido nas regras do scanner.",
                            evidence=executor_hits,
                        )
                    )
                elif lower in rules.medium_signal_directories:
                    findings.append(
                        Finding(
                            risk="LOW",
                            score=6,
                            category="Armazenamento",
                            title="Pasta genérica de scripts ou configurações",
                            path=str(full),
                            detail="Essa pasta pode ser legítima quando aparece sozinha; foi registrada apenas como indício fraco.",
                            evidence=[directory],
                        )
                    )

            for filename in files:
                stats["files_seen"] += 1
                if stats["files_seen"] > MAX_FILES_TO_SCAN:
                    stats["scan_limit_reached"] = True
                    break

                path = current_path / filename
                suffix = path.suffix.lower()
                name_hits = rules.match_name_tokens(filename)
                in_trash = under_trash or _is_under_trash(path.parts, rules)

                if name_hits:
                    findings.append(
                        Finding(
                            risk="MEDIUM" if not in_trash else "HIGH",
                            score=24 if not in_trash else 40,
                            category="Vestígios residuais" if in_trash else "Armazenamento",
                            title="Arquivo com nome suspeito",
                            path=str(path),
                            detail=(
                                "O nome do arquivo corresponde a um executor conhecido nas regras do scanner."
                                if not in_trash
                                else "O arquivo suspeito ainda existe em uma lixeira ou área de reciclagem acessível."
                            ),
                            evidence=name_hits,
                        )
                    )

                if suffix not in rules.script_extensions:
                    continue

                stats["script_candidates_seen"] += 1
                try:
                    st = path.stat()
                    if st.st_size <= 0 or st.st_size > MAX_TEXT_FILE_BYTES:
                        continue
                    data = path.read_bytes()
                except (OSError, PermissionError):
                    continue

                indicator_hits = [
                    name for name, regex in rules.lua_indicators.items() if regex.search(data)
                ]
                text_lower = data[:MAX_TEXT_FILE_BYTES].lower()
                game_hits = [
                    term for term in rules.game_context_terms if term.encode() in text_lower
                ]

                if len(indicator_hits) >= 4:
                    findings.append(
                        Finding(
                            risk="HIGH",
                            score=55 + min(15, len(indicator_hits) * 2),
                            category="Análise Lua",
                            title="Vários indicadores específicos de exploit em Lua",
                            path=str(path),
                            detail="O mesmo script contém várias APIs normalmente associadas a ambientes de exploit.",
                            evidence=sorted(indicator_hits + game_hits),
                        )
                    )
                elif len(indicator_hits) >= 2:
                    findings.append(
                        Finding(
                            risk="MEDIUM",
                            score=32,
                            category="Análise Lua",
                            title="Vários indicadores suspeitos em Lua",
                            path=str(path),
                            detail="Foram encontrados dois ou mais indicadores de ambiente de exploit no mesmo arquivo.",
                            evidence=sorted(indicator_hits + game_hits),
                        )
                    )
                elif len(indicator_hits) == 1:
                    findings.append(
                        Finding(
                            risk="LOW" if not in_trash else "MEDIUM",
                            score=10 if not in_trash else 25,
                            category="Análise Lua" if not in_trash else "Vestígios residuais",
                            title="Indicador suspeito isolado em Lua",
                            path=str(path),
                            detail="Foi encontrado apenas um indicador. Sozinho, ele não é considerado evidência forte.",
                            evidence=sorted(indicator_hits + game_hits),
                        )
                    )
                elif suffix in {".lua", ".luau"} and in_trash:
                    findings.append(
                        Finding(
                            risk="LOW",
                            score=8,
                            category="Vestígios residuais",
                            title="Arquivo Lua encontrado em lixeira",
                            path=str(path),
                            detail="Um arquivo Lua/Luau ainda está presente em uma lixeira ou área de reciclagem acessível.",
                            evidence=[suffix],
                        )
                    )

            if stats["scan_limit_reached"]:
                break

        if stats["scan_limit_reached"]:
            coverage.append(
                CoverageItem(
                    name="Limite da varredura de armazenamento",
                    path=str(root),
                    status="partial",
                    detail=f"A varredura foi interrompida após {MAX_FILES_TO_SCAN} arquivos para evitar uma análise sem limite.",
                )
            )
            break

    return findings, coverage, stats


def inspect_android_app_dirs(rules: Rules) -> tuple[list[Finding], list[CoverageItem], dict]:
    package = rules.roblox_package
    targets = {
        "Android/data": Path("/storage/emulated/0/Android/data") / package,
        "Android/obb": Path("/storage/emulated/0/Android/obb") / package,
    }

    findings: list[Finding] = []
    coverage: list[CoverageItem] = []
    details: dict = {}

    for label, path in targets.items():
        item = {"path": str(path), "status": "unknown", "files_seen": 0}
        try:
            if not path.exists():
                item["status"] = "not-found-or-blocked"
                coverage.append(
                    CoverageItem(
                        name=label,
                        path=str(path),
                        status="not-verified",
                        detail="O caminho não existe ou foi bloqueado pelas restrições do Android. Isso não significa que a área está limpa.",
                    )
                )
            elif not path.is_dir():
                item["status"] = "not-a-directory"
                coverage.append(
                    CoverageItem(label, str(path), "unexpected", "Era esperado encontrar uma pasta nesse caminho."))
            else:
                # Merely being able to stat the directory does not guarantee recursive access.
                readable_any = False
                for current, _dirs, files in safe_walk(path):
                    readable_any = True
                    item["files_seen"] += len(files)
                    for filename in files:
                        fpath = Path(current) / filename
                        hits = rules.match_name_tokens(filename)
                        if hits:
                            findings.append(
                                Finding(
                                    risk="HIGH",
                                    score=45,
                                    category="Dados do aplicativo",
                                    title="Artefato suspeito na área de dados do Roblox",
                                    path=str(fpath),
                                    detail="Um arquivo dentro da área acessível de dados/OBB do Roblox possui nome associado a executor.",
                                    evidence=hits,
                                )
                            )
                item["status"] = "readable" if readable_any else "empty-or-blocked"
                coverage.append(
                    CoverageItem(
                        name=label,
                        path=str(path),
                        status=item["status"],
                        detail="A inspeção foi feita sem alterar arquivos. Um resultado vazio ainda pode ocorrer por bloqueios de acesso do Android.",
                    )
                )
        except PermissionError:
            item["status"] = "permission-denied"
            coverage.append(
                CoverageItem(
                    name=label,
                    path=str(path),
                    status="not-verified",
                    detail="O Android negou acesso a essa área. Ela não pode ser considerada limpa sem verificação.",
                )
            )
        except OSError as exc:
            item["status"] = "os-error"
            coverage.append(
                CoverageItem(label, str(path), "not-verified", f"Erro do sistema: {exc}"))

        details[label] = item

    return findings, coverage, details
