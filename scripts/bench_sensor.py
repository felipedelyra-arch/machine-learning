"""Sensor+detector benchmark under benign write load (synthetic, temp dir only).

Measures, per load level: op->event latency percentiles (write close -> event processed by detector),
sensor-thread CPU seconds (time.thread_time), process max RSS, overflows/lost events.
Usage: python3 scripts/bench_sensor.py [--loads 2000 10000 30000] [--out evidence]
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import platform
import resource
import shutil
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from endguard.rules import Detector  # noqa: E402
from endguard.sensors.linux_inotify import InotifySensor  # noqa: E402


def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(p / 100 * len(xs)))] * 1000, 3)


def writer(root, n, size, q):
    payload = b"benign log line\n" * (size // 16)
    sent, t0 = {}, time.time()
    for i in range(n):
        p = os.path.join(root, f"d{i % 20}", f"f{i}.log")
        sent[p] = time.time()          # before open: latency includes write+close, no race
        with open(p, "wb") as f:
            f.write(payload)
    q.put((sent, time.time() - t0))


def run(n: int, size: int = 4096) -> dict:
    root = tempfile.mkdtemp(prefix="endguard-bench-")
    for d in range(20):
        os.mkdir(os.path.join(root, f"d{d}"))
    sensor, det = InotifySensor(root), Detector(policy_mode="alert")
    op_ts: dict[str, float] = {}
    lat, cpu, stop, decisions, seen = [], [0.0], threading.Event(), [0], []

    def pump():
        c0 = time.thread_time()
        while True:
            evs = sensor.read(0.05)
            for ev in evs:
                decisions[0] += len(det.feed(ev))
                if ev.action == "close_write":
                    seen.append((ev.path, time.time()))
            if stop.is_set() and not evs:
                break
        cpu[0] = time.thread_time() - c0

    th = threading.Thread(target=pump)
    th.start()
    q = mp.Queue()
    w = mp.Process(target=writer, args=(root, n, size, q))   # separate process: no GIL contention
    w.start()
    sent, wall = q.get()
    w.join()
    op_ts.update(sent)
    time.sleep(0.5)
    stop.set()
    th.join()
    for path, t in seen:
        if path in op_ts:
            lat.append(t - op_ts.pop(path))
    st = sensor.status()
    sensor.close()
    shutil.rmtree(root, ignore_errors=True)
    return {"ops": n, "write_wall_s": round(wall, 3), "ops_per_s": round(n / wall),
            "events_matched": len(lat), "ops_without_event": len(op_ts),
            "latency_ms": {"p50": pct(lat, 50), "p95": pct(lat, 95), "p99": pct(lat, 99), "max": pct(lat, 100)},
            "sensor_thread_cpu_s": round(cpu[0], 3), "cpu_ms_per_1k_ops": round(cpu[0] / n * 1e6, 1),
            "decisions": decisions[0], "health": st["health"], "overflows": st["overflows"]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--loads", type=int, nargs="+", default=[2000, 10000, 30000])
    ap.add_argument("--out", default="evidence")
    a = ap.parse_args()
    results = [run(n) for n in a.loads]
    meta = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "platform": platform.platform(),
            "cpus": os.cpu_count(), "python": sys.version.split()[0],
            "max_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
            "note": "writer in separate process; latency = op start -> event processed by detector"}
    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, f"bench-{time.strftime('%Y%m%d-%H%M%S')}.json")
    with open(path, "w") as f:
        json.dump({"meta": meta, "results": results}, f, indent=1)
    print(json.dumps({"meta": meta, "results": results}, indent=1))


if __name__ == "__main__":
    main()
