from __future__ import annotations

import argparse
from pathlib import Path

from . import __version__
from .package import inspect_roblox_package
from .report import build_report, render_text, save_json, save_text
from .rules import Rules
from .storage import inspect_android_app_dirs, scan_shared_storage
from .util import clear_terminal


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="FlexScanner - scanner local de integridade para Roblox no Android")
    parser.add_argument("--no-clear", action="store_true", help="Do not clear the terminal before showing the report")
    parser.add_argument("--output-dir", default="reports", help="Directory where report files are saved")
    parser.add_argument("--config", default="config/signatures.json", help="Rules/signatures JSON path")
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
        scanner_version=__version__,
    )

    json_path = output_dir / "scan-report.json"
    text_path = output_dir / "scan-report.txt"
    save_json(report, json_path)
    save_text(report, text_path)

    if not args.no_clear:
        clear_terminal()

    print(render_text(report), end="")
    print(f"JSON report: {json_path}")
    print(f"Text report: {text_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
