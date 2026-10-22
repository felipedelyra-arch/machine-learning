"""Explainable behavioral rules for ransomware-like mass file damage. Deterministic given the event stream."""
from __future__ import annotations

import math
import os
from collections import Counter, deque
from dataclasses import dataclass

from .schema import Decision, FileEvent

SAMPLE_BYTES = 4096
HIGH_ENTROPY = 7.2      # bits/byte over a 4 KiB sample; ciphertext/compressed ~7.9+


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def sample_entropy(path: str) -> float | None:
    # O_NOFOLLOW: never follow a symlink swapped in after the event.
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        return shannon_entropy(os.read(fd, SAMPLE_BYTES))
    finally:
        os.close(fd)


@dataclass
class Thresholds:
    window_s: float = 10.0
    min_destructive: int = 20      # overwrites/renames/deletes of files that existed before the session
    min_high_entropy: int = 10
    min_high_entropy_ratio: float = 0.6


class Detector:
    """R1 mass_destructive_change + R2 canary_touched.

    Without process attribution (inotify) the window is per watched root, so concurrent benign
    activity can add up with malicious activity; this is a documented coverage limit.
    """
    R1, R2 = "R1.mass_destructive_change", "R2.canary_touched"
    VERSION = 1

    def __init__(self, thresholds: Thresholds | None = None, canaries=(), sampler=sample_entropy,
                 policy_mode: str = "observe"):
        self.t = thresholds or Thresholds()
        self.canaries = {os.path.realpath(c) for c in canaries}
        self.sampler = sampler
        self.policy_mode = policy_mode
        self.created: set[str] = set()      # paths created during this session -> not pre-existing
        self.seen: set[str] = set()         # event_id dedupe
        self.win: deque[tuple[float, str, str, bool]] = deque()  # (ts, kind, event_id, high_entropy)
        self.last_r1 = -math.inf

    def _action(self) -> str:
        return "alert" if self.policy_mode in ("alert", "ask", "contain") else "log"

    def feed(self, ev: FileEvent) -> list[Decision]:
        if ev.event_id in self.seen or ev.action == "overflow":
            return []
        self.seen.add(ev.event_id)
        if len(self.seen) > 100_000:
            self.seen.clear()  # ponytail: coarse dedupe reset; bounded memory beats exact long-range dedupe
        ts = ev.ts_event if ev.ts_event is not None else ev.ts_received
        out: list[Decision] = []

        if ev.action in ("close_write", "modify", "rename_from", "delete") and \
                os.path.realpath(ev.path) in self.canaries:
            out.append(self._decision(self.R2, "high", f"canary {ev.action}: {ev.path}",
                                      {"path": ev.path, "action": ev.action}, (ev.event_id,),
                                      "canary is a planted file; any write is suspicious but not proof"))

        kind = None
        if ev.action == "create":
            self.created.add(ev.path)
        elif ev.action == "rename_to":
            self.created.add(ev.path)
        elif ev.action == "close_write":
            ent = self.sampler(ev.path)
            high = ent is not None and ent >= HIGH_ENTROPY
            kind = "write_new" if ev.path in self.created else "overwrite"
            self.win.append((ts, kind, ev.event_id, high))
        elif ev.action in ("rename_from", "delete"):
            if ev.path in self.created:
                self.created.discard(ev.path)
            else:
                kind = ev.action
                self.win.append((ts, kind, ev.event_id, False))

        if kind is None:
            return out
        horizon = max(ts, self.win[-1][0]) - self.t.window_s
        while self.win and self.win[0][0] < horizon:
            self.win.popleft()
        f = self.features()
        if (f["destructive"] >= self.t.min_destructive and f["high_entropy_writes"] >= self.t.min_high_entropy
                and f["high_entropy_ratio"] >= self.t.min_high_entropy_ratio
                and ts - self.last_r1 >= self.t.window_s):
            self.last_r1 = ts
            out.append(self._decision(
                self.R1, "high",
                f"{f['destructive']} destructive ops on pre-existing files, "
                f"{f['high_entropy_writes']} high-entropy writes in {self.t.window_s:.0f}s",
                f, tuple(e[2] for e in list(self.win)[-50:]),
                "no process attribution; in-place compression (gzip -r) and bulk re-encoding match this pattern"))
        return out

    def features(self) -> dict:
        kinds = Counter(k for _, k, _, _ in self.win)
        writes = kinds["overwrite"] + kinds["write_new"]
        high = sum(1 for _, k, _, h in self.win if h)
        return {
            "overwrite": kinds["overwrite"], "write_new": kinds["write_new"],
            "rename_existing": kinds["rename_from"], "delete_existing": kinds["delete"],
            "destructive": kinds["overwrite"] + kinds["rename_from"] + kinds["delete"],
            "high_entropy_writes": high,
            "high_entropy_ratio": round(high / writes, 3) if writes else 0.0,
            "window_s": self.t.window_s,
        }

    def _decision(self, rule, sev, summary, feats, evidence, uncertainty) -> Decision:
        return Decision(rule_id=rule, rule_version=self.VERSION, severity=sev, summary=summary,
                        features=feats, evidence=evidence, uncertainty=uncertainty,
                        policy_mode=self.policy_mode, action=self._action())
