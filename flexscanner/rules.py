from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


class Rules:
    def __init__(self, config_path: Path):
        raw = json.loads(config_path.read_text(encoding="utf-8"))
        self.raw: dict[str, Any] = raw

        self.roblox_package: str = raw["roblox_package"]
        self.trusted_installers = {x.casefold() for x in raw.get("trusted_installers", [])}
        self.executor_names = {x.casefold() for x in raw.get("executor_names", [])}
        self.high_signal_directories = {x.casefold() for x in raw.get("high_signal_directories", [])}
        self.medium_signal_directories = {x.casefold() for x in raw.get("medium_signal_directories", [])}
        self.trash_directory_names = {x.casefold() for x in raw.get("trash_directory_names", [])}
        self.script_extensions = {x.casefold() for x in raw.get("script_extensions", [])}
        self.game_context_terms = {x.casefold() for x in raw.get("game_context_terms", [])}
        self.official_roblox_cert_sha256 = {
            x.replace(":", "").strip().lower()
            for x in raw.get("official_roblox_cert_sha256", [])
            if x.strip()
        }

        self.lua_indicators: dict[str, re.Pattern[bytes]] = {}
        for name, pattern in raw.get("lua_indicators", {}).items():
            self.lua_indicators[name] = re.compile(pattern.encode(), re.IGNORECASE)

    def match_name_tokens(self, text: str) -> list[str]:
        lower = text.casefold()
        return sorted(name for name in self.executor_names if name in lower)
