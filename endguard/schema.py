"""Versioned event/decision contracts. Everything crossing a layer boundary is validated here."""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field

SCHEMA_VERSION = 1
ACTIONS = {"create", "close_write", "modify", "rename_from", "rename_to", "delete", "overflow"}
MAX_PATH = 4096


class SchemaError(ValueError):
    pass


@dataclass(frozen=True)
class ProcessRef:
    # PID alone is ambiguous (reuse); start_time disambiguates. Both None when the sensor cannot attribute.
    pid: int | None = None
    start_time: float | None = None
    exe: str | None = None


@dataclass(frozen=True)
class FileEvent:
    action: str
    path: str
    sensor: str
    platform: str
    ts_received: float = field(default_factory=time.time)
    ts_event: float | None = None          # inotify gives no kernel timestamp
    dev: int | None = None
    inode: int | None = None
    cookie: int = 0                        # links rename_from/rename_to
    process: ProcessRef = ProcessRef()
    quality: tuple[str, ...] = ()          # e.g. "no_process_attribution", "stat_failed"
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        if self.schema_version != SCHEMA_VERSION:
            raise SchemaError(f"unsupported schema_version {self.schema_version}")
        if self.action not in ACTIONS:
            raise SchemaError(f"bad action {self.action!r}")
        if not isinstance(self.path, str) or len(self.path) > MAX_PATH or "\x00" in self.path:
            raise SchemaError("bad path")
        if not isinstance(self.ts_received, (int, float)):
            raise SchemaError("bad ts_received")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "FileEvent":
        if not isinstance(d, dict):
            raise SchemaError("event must be an object")
        d = dict(d)
        proc = d.pop("process", None) or {}
        if not isinstance(proc, dict) or set(proc) - {"pid", "start_time", "exe"}:
            raise SchemaError("bad process")
        unknown = set(d) - set(cls.__dataclass_fields__)
        if unknown:
            raise SchemaError(f"unknown fields {sorted(unknown)}")
        d["quality"] = tuple(d.get("quality", ()))
        try:
            return cls(process=ProcessRef(**proc), **d)
        except TypeError as e:
            raise SchemaError(str(e)) from e


@dataclass(frozen=True)
class Decision:
    rule_id: str
    rule_version: int
    severity: str                          # low | medium | high
    summary: str
    features: dict
    evidence: tuple[str, ...]              # event_ids (capped)
    uncertainty: str
    policy_mode: str
    action: str                            # what the policy allowed: log | alert
    ts: float = field(default_factory=time.time)
    decision_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict:
        return asdict(self)
