from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path


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
    # ANSI clear + cursor home. Avoids depending exclusively on the `clear` binary.
    print("\033[2J\033[H", end="", flush=True)


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
