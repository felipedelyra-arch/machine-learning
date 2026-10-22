"""endguard CLI. Observation/alert only: this increment has no blocking or containment."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import simulator
from .rules import Detector, Thresholds
from .schema import FileEvent, SchemaError
from .status import effective_health
from .store import Store

MODES = ("observe", "alert")       # "ask"/"contain" intentionally not offered yet


def _print(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def cmd_watch(a):
    from .sensors.linux_inotify import InotifySensor
    store, sensor = Store(a.db), InotifySensor(a.path)
    det = Detector(canaries=a.canary or (), policy_mode=a.mode)
    status = lambda: {**sensor.status(), "pid": os.getpid()}  # noqa: E731
    store.add_health(status())
    print(f"watching {sensor.root} health={sensor.health} (observational, cannot block)", file=sys.stderr)
    deadline = time.monotonic() + a.seconds if a.seconds else None
    last_h = 0.0
    try:
        while deadline is None or time.monotonic() < deadline:
            for ev in sensor.read():
                for d in det.feed(ev):
                    store.add_decision(d)
                    print(json.dumps({"ALERT" if d.action == "alert" else "LOG": d.summary,
                                      "rule": d.rule_id, "id": d.decision_id}), flush=True)
            if time.monotonic() - last_h > 5:
                store.add_health(status())
                last_h = time.monotonic()
    except KeyboardInterrupt:
        pass
    finally:
        store.add_health({**sensor.status(), "health": "disabled", "causes": ["watch stopped"]})
        sensor.close()


def cmd_replay(a):
    det = Detector(canaries=a.canary or (), policy_mode=a.mode)
    out, bad = [], 0
    with open(a.file) as f:
        events = []
        for line in f:
            try:
                events.append(FileEvent.from_dict(json.loads(line)))
            except (ValueError, TypeError, SchemaError):
                bad += 1
    events.sort(key=lambda e: e.ts_event if e.ts_event is not None else e.ts_received)
    for ev in events:
        out += [d.to_dict() for d in det.feed(ev)]
    _print({"events": len(events), "rejected": bad, "decisions": out})


def cmd_status(a):
    _print(effective_health(a.db))


def cmd_decisions(a):
    _print(Store(a.db).decisions(a.limit) if os.path.exists(a.db) else [])


def cmd_mail(a):
    from .mail import MAX_BYTES, analyze_eml_isolated
    with open(a.file, "rb") as f:
        data = f.read(MAX_BYTES + 1)
    try:
        _print(analyze_eml_isolated(data, frozenset(a.trusted_authserv or ())))
    except ValueError as e:
        sys.exit(f"endguard mail: {e}")


def cmd_simulate(a):
    lab = simulator.make_lab(a.files, a.seed)
    print(f"lab={lab}", file=sys.stderr, flush=True)
    if a.delay:
        time.sleep(a.delay)
    log = simulator.run(lab, a.variant, a.seed, a.rate)
    _print({"lab": lab, "variant": a.variant, "ops": len(log)})


def main(argv=None):
    p = argparse.ArgumentParser("endguard")
    p.add_argument("--db", default=os.path.expanduser("~/.endguard.db"))
    sub = p.add_subparsers(dest="cmd", required=True)
    w = sub.add_parser("watch"); w.add_argument("path"); w.add_argument("--seconds", type=float)
    r = sub.add_parser("replay"); r.add_argument("file")
    for x in (w, r):
        x.add_argument("--mode", choices=MODES, default="observe")
        x.add_argument("--canary", action="append")
    sub.add_parser("status")
    d = sub.add_parser("decisions"); d.add_argument("--limit", type=int, default=20)
    m = sub.add_parser("mail", help="offline .eml analysis (not inbox protection)")
    m.add_argument("file")
    m.add_argument("--trusted-authserv", action="append",
                   help="authserv-id of YOUR receiving MTA; other Authentication-Results are ignored")
    s = sub.add_parser("simulate")
    s.add_argument("--variant", choices=simulator.VARIANTS, default="overwrite")
    s.add_argument("--files", type=int, default=200); s.add_argument("--seed", type=int, default=1)
    s.add_argument("--rate", type=float, default=200.0); s.add_argument("--delay", type=float, default=0)
    a = p.parse_args(argv)
    globals()[f"cmd_{a.cmd}"](a)


if __name__ == "__main__":
    main()
