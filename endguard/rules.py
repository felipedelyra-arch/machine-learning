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
    VERSION = 3

    def __init__(self, thresholds: Thresholds | None = None, canaries=(), sampler=None,
                 policy_mode: str = "observe"):
        self.t = thresholds or Thresholds()
        self.canaries = {os.path.realpath(c) for c in canaries}
        self.sampler = sampler or (lambda ev: ev.content_entropy)
        self.policy_mode = policy_mode
        self.new_inodes: OrderedDict = OrderedDict()   # (dev, ino) | ("path", p) -> creation ts
        self.path_key: OrderedDict = OrderedDict()     # path -> key of a session-created inode
        self.renames: OrderedDict = OrderedDict()      # cookie -> (rename_from counted, key)
        self._now = 0.0
        self.seen: OrderedDict[str, None] = OrderedDict()         # event_id dedupe (replays)
        self.win: deque[tuple[float, str, str, bool | None]] = deque()  # (ts, kind, event_id, high_entropy)
        self.kinds: Counter = Counter()
        self.sampled = self.high = 0
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

    def _fresh(self, ts_created) -> bool:
        return ts_created is not None and self._now - ts_created <= self.t.created_ttl_s

    def _is_new(self, path: str, key=None) -> bool:
        # "new" = inode created during this session (by its create event), never granted by rename/hardlink
        if key is not None:          # inode known: path state is never consulted (may be stale)
            return self._fresh(self.new_inodes.get(key))
        pk = self.path_key.get(path)
        return pk is not None and self._fresh(self.new_inodes.get(pk))

    def feed(self, ev: FileEvent) -> list[Decision]:
        if ev.event_id in self.seen:
            return []
        self._bounded_put(self.seen, ev.event_id, None)
        if ev.action == "overflow":
            self.coverage_gaps += 1
            # lost events -> newness state may be stale; forget it so everything counts as pre-existing
            self.new_inodes.clear(); self.path_key.clear(); self.renames.clear()
            return []
        ts = self._now = ev.ts_event if ev.ts_event is not None else ev.ts_received
        key = (ev.dev, ev.inode) if ev.dev is not None and ev.inode is not None else None
        out: list[Decision] = []

        if ev.action != "create" and os.path.realpath(ev.path) in self.canaries:
            rp = os.path.realpath(ev.path)
            if ts - self.last_r2.get(rp, -math.inf) >= self.t.window_s:
                self.last_r2[rp] = ts
                out.append(self._decision(self.R2, "high", f"canary {ev.action}: {ev.path}",
                                          {"path": ev.path, "action": ev.action}, (ev.event_id,),
                                          "canary is a planted file; any change is suspicious but not proof"))

        kind, high = None, None
        if ev.action == "create":
            if not {"multi_link", "stat_failed"} & set(ev.quality):   # hardlink alias / unknown inode: not new
                k = key or ("path", ev.path)
                self._bounded_put(self.new_inodes, k, ts)
                self._bounded_put(self.path_key, ev.path, k)
        elif ev.action == "close_write":
            ent = self.sampler(ev)
            high = None if ent is None else ent >= HIGH_ENTROPY
            if "no_modify_seen" in ev.quality and high is False:
                return out   # likely open-for-write probe; unsampled (gone/unreadable) still counts
            kind = "write_new" if self._is_new(ev.path, key) else "overwrite"
        elif ev.action == "rename_from":
            counted = not self._is_new(ev.path)
            self._bounded_put(self.renames, ev.cookie, (counted, self.path_key.pop(ev.path, None)))
            kind = "rename_from" if counted else None
        elif ev.action == "rename_to":
            info = self.renames.pop(ev.cookie, None)
            if info is None or (not info[0] and not self._is_new(ev.path)):
                kind = "replace"   # moved in from outside, or tmp-then-rename over a non-new file
            if info is not None and info[1] is not None:
                self._bounded_put(self.path_key, ev.path, info[1])   # inode keeps its own status
            else:
                self.path_key.pop(ev.path, None)
        elif ev.action == "delete":
            if self._is_new(ev.path):
                self.new_inodes.pop(self.path_key.pop(ev.path), None)
            else:
                kind = "delete"
                self.new_inodes.pop(self.path_key.pop(ev.path, None), None)

        if kind is None:
            return out
        self._win_add((ts, kind, ev.event_id, high), +1)
        horizon = max(ts, self.win[-1][0]) - self.t.window_s
        while self.win and self.win[0][0] < horizon:
            self._win_add(self.win[0], -1)
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

    def _win_add(self, item, sign: int):
        # running counters keep features() O(1); the window can hold thousands of events
        if sign > 0:
            self.win.append(item)
        else:
            self.win.popleft()
        _, kind, _, high = item
        self.kinds[kind] += sign
        if kind in ("overwrite", "write_new") and high is not None:
            self.sampled += sign
        if high:
            self.high += sign

    def features(self) -> dict:
        k = self.kinds
        return {
            "overwrite": k["overwrite"], "write_new": k["write_new"],
            "rename_existing": k["rename_from"], "replace": k["replace"], "delete_existing": k["delete"],
            "destructive": k["overwrite"] + k["rename_from"] + k["replace"] + k["delete"],
            "high_entropy_writes": self.high,
            "unsampled_writes": k["overwrite"] + k["write_new"] - self.sampled,
            "high_entropy_ratio": round(self.high / self.sampled, 3) if self.sampled else 0.0,
            "coverage_gaps": self.coverage_gaps,
            "window_s": self.t.window_s,
        }

    def _decision(self, rule, sev, summary, feats, evidence, uncertainty) -> Decision:
        return Decision(rule_id=rule, rule_version=self.VERSION, severity=sev, summary=summary,
                        features=feats, evidence=evidence, uncertainty=uncertainty,
                        policy_mode=self.policy_mode, action=self._action())
