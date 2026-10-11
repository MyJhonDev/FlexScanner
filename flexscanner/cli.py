from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .package import inspect_roblox_package
from .delta import inspect_delta_executor
from .report import build_report, render_text, save_json, save_text
from .rules import Rules
from .storage import inspect_android_app_dirs, scan_shared_storage
from .util import clear_terminal


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FlexScanner - scanner de integridade para Roblox no Android")
    parser.add_argument("--no-clear", action="store_true", help="Não limpar o terminal antes de exibir o relatório")
    parser.add_argument("--output-dir", default="reports", help="Pasta onde os relatórios serão salvos")
    parser.add_argument("--config", default="config/signatures.json", help="Arquivo JSON com as regras e assinaturas")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    project_root = Path(__file__).resolve().parent.parent

    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = project_root / config_path

    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = project_root / output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    rules = Rules(config_path)

    findings = []
    coverage = []

    storage_findings, storage_coverage, storage_stats = scan_shared_storage(rules)
    findings.extend(storage_findings)
    coverage.extend(storage_coverage)

    delta_findings, delta_coverage, delta_info = inspect_delta_executor(rules)
    findings.extend(delta_findings)
    coverage.extend(delta_coverage)

    package_findings, package_coverage, package_info = inspect_roblox_package(rules)
    findings.extend(package_findings)
    coverage.extend(package_coverage)

    android_findings, android_coverage, android_dirs = inspect_android_app_dirs(rules)
    findings.extend(android_findings)
    coverage.extend(android_coverage)

    report = build_report(
        findings=findings,
        coverage=coverage,
        storage_stats=storage_stats,
        package_info=package_info,
        android_dirs=android_dirs,
        delta_info=delta_info,
        scanner_version=__version__,
    )

    json_path = output_dir / "scan-report.json"
    text_path = output_dir / "scan-report.txt"
    save_json(report, json_path)
    save_text(report, text_path)

    if not args.no_clear:
        clear_terminal()

    use_color = sys.stdout.isatty()
    print(render_text(report, use_color=use_color), end="")
    print(f"Relatório JSON : {json_path}")
    print(f"Relatório TXT  : {text_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
