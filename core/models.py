"""
Core data models.

All modules return Finding objects in the same format, so the
orchestrator, the correlator and the report never need to know
which tool produced them.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum


class EntityType(str, Enum):
    """Entity types the system knows about."""
    NAME = "name"
    USERNAME = "username"
    EMAIL = "email"
    PHONE = "phone"
    DOMAIN = "domain"
    IP = "ip"
    ORG = "org"
    PROFILE_URL = "profile_url"
    BREACH = "breach"
    SUBDOMAIN = "subdomain"
    HOST = "host"
    UNKNOWN = "unknown"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Finding:
    """
    A single finding. It is both input (seed) and output: anything a module
    finds can be queued again as a seed for other modules.
    """
    type: str                      # EntityType value
    value: str                     # the actual value (email, username...)
    source: str = "input"          # which module/source produced it
    parent: str | None = None      # the seed it came from (for the graph)
    confidence: float = 0.5        # 0.0 - 1.0
    depth: int = 0                 # number of pivot hops from the original input
    meta: dict = field(default_factory=dict)  # any extras (breach names, raw...)
    found_at: str = field(default_factory=_now)

    def __post_init__(self) -> None:
        # Always normalize the type to a plain string. Otherwise an EntityType
        # member and its string value produce different keys (the f-string of
        # a str Enum gives "EntityType.DOMAIN" on older Pythons), which breaks
        # dedup and the graph.
        if isinstance(self.type, EntityType):
            self.type = self.type.value

    @property
    def key(self) -> str:
        """Unique dedup key: type + normalized value."""
        return f"{self.type}:{self.value.strip().lower()}"

    @property
    def node_id(self) -> str:
        """Stable id for the graph."""
        return hashlib.md5(self.key.encode()).hexdigest()[:10]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Target:
    """The investigation target. Holds the original inputs and metadata."""
    label: str                     # display name for the report
    seeds: list[Finding] = field(default_factory=list)
    started_at: str = field(default_factory=_now)

    def add_seed(self, type_: str, value: str) -> None:
        self.seeds.append(
            Finding(type=type_, value=value, source="input", confidence=1.0, depth=0)
        )
