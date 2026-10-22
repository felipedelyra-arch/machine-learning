"""Explainable behavioral rules for ransomware-like mass file damage. Deterministic given the event stream
(content entropy travels inside the event; the detector never reads the filesystem)."""
from __future__ import annotations

import math
import os
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass

from .features import HIGH_ENTROPY
from .schema import Decision, FileEvent

MAX_TRACKED = 100_000


@dataclass
class Thresholds:
    window_s: float = 10.0
    min_destructive: int = 20      # overwrites/renames/replaces/deletes of files that existed before
    min_high_entropy: int = 10
    min_high_entropy_ratio: float = 0.6
    created_ttl_s: float = 60.0    # after this a session-created file counts as pre-existing again


class Detector:
    """R1 mass_destructive_change + R2 canary_touched.

    Without process attribution (inotify) the window is per watched root, so concurrent benign
    activity can add up with malicious activity; this is a documented coverage limit.
    """
    R1, R2 = "R1.mass_destructive_change", "R2.canary_touched"
    VERSION = 2

    def __init__(self, thresholds: Thresholds | None = None, canaries=(), sampler=None,
                 policy_mode: str = "observe"):
        self.t = thresholds or Thresholds()
        self.canaries = {os.path.realpath(c) for c in canaries}
        self.sampler = sampler or (lambda ev: ev.content_entropy)
        self.policy_mode = policy_mode
        self.created: OrderedDict[str, float] = OrderedDict()   # path -> creation ts
        self.renames: OrderedDict[int, bool] = OrderedDict()     # cookie -> rename_from already counted
        self.seen: OrderedDict[str, None] = OrderedDict()         # event_id dedupe (replays)
        self.win: deque[tuple[float, str, str, bool | None]] = deque()  # (ts, kind, event_id, high_entropy)
        self.coverage_gaps = 0
        self.last_r1 = -math.inf
        self.last_r2: dict[str, float] = {}

    def _action(self) -> str:
        return "alert" if self.policy_mode in ("alert", "ask", "contain") else "log"

    @staticmethod
    def _bounded_put(od: OrderedDict, k, v):
        od[k] = v
        od.move_to_end(k)
        if len(od) > MAX_TRACKED:
            od.popitem(last=False)   # oldest forgotten -> treated as pre-existing (conservative)

    def _is_new(self, path: str, ts: float) -> bool:
        c = self.created.get(path)
        return c is not None and ts - c <= self.t.created_ttl_s

    def feed(self, ev: FileEvent) -> list[Decision]:
        if ev.event_id in self.seen:
            return []
        self._bounded_put(self.seen, ev.event_id, None)
        if ev.action == "overflow":
            self.coverage_gaps += 1
            return []
        ts = ev.ts_event if ev.ts_event is not None else ev.ts_received
        out: list[Decision] = []

        if ev.action != "create" and os.path.realpath(ev.path) in self.canaries:
            key = os.path.realpath(ev.path)
            if ts - self.last_r2.get(key, -math.inf) >= self.t.window_s:
                self.last_r2[key] = ts
                out.append(self._decision(self.R2, "high", f"canary {ev.action}: {ev.path}",
                                          {"path": ev.path, "action": ev.action}, (ev.event_id,),
                                          "canary is a planted file; any change is suspicious but not proof"))

        kind, high = None, None
        if ev.action == "create":
            self._bounded_put(self.created, ev.path, ts)
        elif ev.action == "close_write":
            ent = self.sampler(ev)
            high = None if ent is None else ent >= HIGH_ENTROPY
            kind = "write_new" if self._is_new(ev.path, ts) else "overwrite"
        elif ev.action == "rename_from":
            counted = not self._is_new(ev.path, ts)
            self.created.pop(ev.path, None)
            self._bounded_put(self.renames, ev.cookie, counted)
            kind = "rename_from" if counted else None
        elif ev.action == "rename_to":
            counted = self.renames.pop(ev.cookie, None)
            if not counted and not self._is_new(ev.path, ts):
                kind = "replace"     # tmp-then-rename over a (possibly) pre-existing file; inotify can't tell
            self._bounded_put(self.created, ev.path, ts)
        elif ev.action == "delete":
            if self._is_new(ev.path, ts):
                self.created.pop(ev.path, None)
            else:
                kind = "delete"

        if kind is None:
            return out
        self.win.append((ts, kind, ev.event_id, high))
        horizon = max(ts, self.win[-1][0]) - self.t.window_s
        while self.win and self.win[0][0] < horizon:
            self.win.popleft()
        f = self.features()
        if (f["destructive"] >= self.t.min_destructive and f["high_entropy_writes"] >= self.t.min_high_entropy
                and f["high_entropy_ratio"] >= self.t.min_high_entropy_ratio
                and ts - self.last_r1 >= self.t.window_s):
            self.last_r1 = ts
            unc = "no process attribution; in-place compression (gzip -r) and bulk re-encoding match this pattern"
            if self.coverage_gaps:
                unc += f"; {self.coverage_gaps} sensor overflow(s): events were lost"
            out.append(self._decision(
                self.R1, "high",
                f"{f['destructive']} destructive ops on pre-existing files, "
                f"{f['high_entropy_writes']} high-entropy writes in {self.t.window_s:.0f}s",
                f, tuple(e[2] for e in list(self.win)[-50:]), unc))
        return out

    def features(self) -> dict:
        kinds = Counter(k for _, k, _, _ in self.win)
        sampled = sum(1 for _, k, _, h in self.win if k in ("overwrite", "write_new") and h is not None)
        high = sum(1 for _, _, _, h in self.win if h)
        return {
            "overwrite": kinds["overwrite"], "write_new": kinds["write_new"],
            "rename_existing": kinds["rename_from"], "replace": kinds["replace"], "delete_existing": kinds["delete"],
            "destructive": kinds["overwrite"] + kinds["rename_from"] + kinds["replace"] + kinds["delete"],
            "high_entropy_writes": high,
            "unsampled_writes": kinds["overwrite"] + kinds["write_new"] - sampled,
            "high_entropy_ratio": round(high / sampled, 3) if sampled else 0.0,
            "coverage_gaps": self.coverage_gaps,
            "window_s": self.t.window_s,
        }

    def _decision(self, rule, sev, summary, feats, evidence, uncertainty) -> Decision:
        return Decision(rule_id=rule, rule_version=self.VERSION, severity=sev, summary=summary,
                        features=feats, evidence=evidence, uncertainty=uncertainty,
                        policy_mode=self.policy_mode, action=self._action())
