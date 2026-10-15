"""Building blocks: severity levels, findings and the score."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import List


class Level(IntEnum):
    OK = 0      # all good
    INFO = 1    # good to know, not a problem
    WARN = 2    # worth a look
    CRIT = 3    # act now

    @property
    def label(self) -> str:
        return {0: "OK", 1: "Info", 2: "Warning", 3: "Critical"}[self.value]


# How many points a finding subtracts from the score (100)
WEIGHTS = {Level.OK: 0, Level.INFO: 0, Level.WARN: 7, Level.CRIT: 20}


@dataclass
class Finding:
    title: str                      # short headline
    level: Level
    detail: str = ""                # what exactly was found
    explain: str = ""               # what does it mean? (beginner friendly)
    fix: str = ""                   # what can I do? Commands go in `backticks`.
    items: List[str] = field(default_factory=list)  # affected things (ports, files, ...)

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "level": self.level.name,
            "detail": self.detail,
            "explain": self.explain,
            "fix": self.fix,
            "items": self.items,
        }


@dataclass
class CheckResult:
    id: str
    title: str
    findings: List[Finding]
    seconds: float = 0.0

    @property
    def worst(self) -> Level:
        return max((f.level for f in self.findings), default=Level.OK)


def plural(n: int, word: str, many: str = "") -> str:
    """plural(1, "port") -> "1 port", plural(3, "port") -> "3 ports"."""
    return f"{n} {word if n == 1 else (many or word + 's')}"


def score(results: List[CheckResult]) -> int:
    penalty = sum(WEIGHTS[f.level] for r in results for f in r.findings)
    return max(0, 100 - penalty)


def mood(points: int) -> str:
    if points >= 85:
        return "happy"
    if points >= 60:
        return "neutral"
    return "worried"
