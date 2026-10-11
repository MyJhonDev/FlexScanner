from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from datetime import timedelta, timezone, tzinfo
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def sao_paulo_timezone() -> tzinfo:
    """Retorna America/Sao_Paulo e nunca derruba o scanner se tzdata faltar."""
    try:
        return ZoneInfo("America/Sao_Paulo")
    except ZoneInfoNotFoundError:
        # O Brasil não usa horário de verão desde 2019. Para aparelhos sem
        # base tzdata, UTC-03:00 mantém o relatório utilizável no Termux.
        return timezone(timedelta(hours=-3), name="America/Sao_Paulo")


def safe_timezone(name: str | None) -> tzinfo:
    """Tenta carregar o fuso informado; usa São Paulo como fallback seguro."""
    if name:
        try:
            return ZoneInfo(name)
        except ZoneInfoNotFoundError:
            pass
    return sao_paulo_timezone()


def run_cmd(args: list[str], timeout: int = 12) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError) as exc:
        return 127, str(exc)


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def clear_terminal() -> None:
    """Limpa tela e histórico visível do terminal antes do relatório."""
    try:
        if shutil.which("clear"):
            subprocess.run(["clear"], check=False)
    except OSError:
        pass

    # 3J: apaga o scrollback quando suportado.
    # 2J: limpa a tela atual.
    # H : move o cursor para o início.
    try:
        sys.stdout.write("\033[3J\033[2J\033[H")
        sys.stdout.flush()
    except (OSError, ValueError):
        pass


def safe_realpath(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:
        return path


def is_readable(path: Path) -> bool:
    try:
        return path.exists() and os.access(path, os.R_OK)
    except OSError:
        return False
