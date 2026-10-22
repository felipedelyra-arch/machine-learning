"""Versioned event/decision contracts. Everything crossing a layer boundary is validated here."""
from __future__ import annotations

import math
import time
import uuid
from dataclasses import asdict, dataclass, field

SCHEMA_VERSION = 1
ACTIONS = {"create", "close_write", "modify", "rename_from", "rename_to", "delete", "overflow"}
MAX_PATH = 4096
QUALITY_FLAGS = {"no_process_attribution", "no_kernel_timestamp", "stat_failed", "multi_link",
                 "no_modify_seen", "replayed"}


class SchemaError(ValueError):
    pass


def _num(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


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
    content_entropy: float | None = None   # sampled by the sensor at read time; detector never reads disk
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self):
        if self.schema_version != SCHEMA_VERSION:
            raise SchemaError(f"unsupported schema_version {self.schema_version}")
        if self.action not in ACTIONS:
            raise SchemaError(f"bad action {self.action!r}")
        if not isinstance(self.path, str) or len(self.path) > MAX_PATH or "\x00" in self.path:
            raise SchemaError("bad path")
        for name in ("sensor", "platform", "event_id"):
            v = getattr(self, name)
            if not isinstance(v, str) or not 0 < len(v) <= 128:
                raise SchemaError(f"bad {name}")
        for name, opt in (("ts_received", False), ("ts_event", True), ("content_entropy", True)):
            v = getattr(self, name)
            if not (opt and v is None) and (not _num(v) or not math.isfinite(v)):
                raise SchemaError(f"bad {name}")
        for name in ("dev", "inode", "cookie"):
            v = getattr(self, name)
            if not (v is None and name != "cookie") and (not isinstance(v, int) or isinstance(v, bool) or v < 0):
                raise SchemaError(f"bad {name}")
        p = self.process
        if not (p.pid is None or (isinstance(p.pid, int) and not isinstance(p.pid, bool))) or \
                not (p.start_time is None or _num(p.start_time)) or not (p.exe is None or isinstance(p.exe, str)):
            raise SchemaError("bad process")
        if not isinstance(self.quality, tuple) or not all(q in QUALITY_FLAGS for q in self.quality):
            raise SchemaError("bad quality")

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
        q = d.get("quality", ())
        if not isinstance(q, (list, tuple)):
            raise SchemaError("bad quality")
        d["quality"] = tuple(q)
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
    evidence: tuple[str, ...]              # event_ids (capped); events themselves are not persisted
    uncertainty: str
    policy_mode: str
    action: str                            # what the policy allowed: log | alert
    evidence_summary: tuple = ()           # (action, path, ts) of the latest evidence events: resolvable later
    ts: float = field(default_factory=time.time)
    decision_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict:
        return asdict(self)
