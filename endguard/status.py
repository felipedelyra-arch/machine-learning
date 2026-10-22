"""Effective sensor health as shown to users: never 'healthy-looking' when the sensor is not running."""
from __future__ import annotations

import os
import time

from .store import Store

STALE_S = 30


def _alive(pid: int) -> bool:
    # ponytail: pid liveness only (same host, pid reuse possible); per-sensor ids when multiple watchers share a DB
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass
    return True


def effective_health(db: str) -> dict:
    h = Store(db, readonly=True).last_health() if os.path.exists(db) else None
    if h is None:
        return {"health": "disabled", "causes": ["no sensor has run"]}
    if h["health"] != "disabled":
        age = time.time() - h["recorded_at"]
        if age > STALE_S or age < -5:
            h = {**h, "health": "degraded", "causes": h["causes"] + ["no fresh heartbeat (stale or clock skew)"]}
        elif h.get("pid") and not _alive(h["pid"]):
            h = {**h, "health": "degraded", "causes": h["causes"] + [f"sensor process {h['pid']} not running"]}
    return h
