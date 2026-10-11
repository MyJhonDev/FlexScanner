from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    risk: str
    score: int
    category: str
    title: str
    path: str = ""
    detail: str = ""
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CoverageItem:
    name: str
    path: str
    status: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
