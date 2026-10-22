import json
import os
import sqlite3
import stat
import struct
import tempfile
import unittest
from unittest import mock

from endguard import simulator
from endguard.cli import main as cli_main
from endguard.rules import Detector, Thresholds, shannon_entropy
from endguard.schema import FileEvent, SchemaError
from endguard.sensors import linux_inotify as ino
from endguard.store import Store


def ev(action, path, ts, **kw):
    return FileEvent(action, path, "test", "linux", ts_received=ts, **kw)


def det(high=True, **kw):
    return Detector(Thresholds(), sampler=lambda p: 7.99 if high else 4.0, policy_mode="alert", **kw)


def burst(d, n=25, action="close_write", t0=100.0, step=0.01):
    out = []
    for i in range(n):
        out += d.feed(ev(action, f"/lab/f{i}", t0 + i * step))
    return out


class SchemaTests(unittest.TestCase):
    def test_rejects_malformed(self):
        for bad in [{"action": "chmod", "path": "/x", "sensor": "s", "platform": "linux"},
                    {"action": "create", "path": "/x\x00y", "sensor": "s", "platform": "linux"},
                    {"action": "create", "path": "/x", "sensor": "s", "platform": "linux", "evil": 1},
                    {"action": "create", "path": "/x", "sensor": "s", "platform": "linux", "schema_version": 99},
                    {"action": "create", "path": "/x", "sensor": "s", "platform": "linux", "process": {"cmd": "rm"}},
                    ["not", "an", "object"]]:
            with self.assertRaises(SchemaError, msg=bad):
                FileEvent.from_dict(bad)

    def test_roundtrip(self):
        e = ev("create", "/a", 1.0)
        self.assertEqual(FileEvent.from_dict(json.loads(json.dumps(e.to_dict()))), e)


class DetectorTests(unittest.TestCase):
    def test_mass_high_entropy_overwrite_alerts_once(self):
        out = burst(det(), 60)
        self.assertEqual([d.rule_id for d in out], [Detector.R1])
        self.assertEqual(out[0].action, "alert")
        self.assertIn("no process attribution", out[0].uncertainty)

    def test_low_entropy_overwrites_do_not_alert(self):
        self.assertEqual(burst(det(high=False), 60), [])

    def test_below_threshold_does_not_alert(self):
        self.assertEqual(burst(det(), 19), [])

    def test_slow_rate_falls_out_of_window(self):
        self.assertEqual(burst(det(), 60, step=1.0), [])

    def test_files_created_in_session_are_not_destructive(self):
        d = det()
        for i in range(30):
            d.feed(ev("create", f"/lab/f{i}", 100 + i * 0.01))
        self.assertEqual(burst(d, 30), [])          # writes to new files
        self.assertEqual(burst(d, 30, "delete", t0=101), [])

    def test_duplicate_events_not_double_counted(self):
        d = det()
        e = ev("close_write", "/lab/x", 100.0)
        for _ in range(50):
            d.feed(e)
        self.assertEqual(d.features()["overwrite"], 1)

    def test_out_of_order_within_window_still_detects(self):
        d = det()
        evs = [ev("close_write", f"/lab/f{i}", 100 + i * 0.01) for i in range(30)]
        out = []
        for e in reversed(evs):
            out += d.feed(e)
        self.assertEqual([x.rule_id for x in out], [Detector.R1])

    def test_canary(self):
        with tempfile.TemporaryDirectory() as t:
            c = os.path.join(t, "canary.docx")
            open(c, "w").close()
            out = det(canaries=[c]).feed(ev("close_write", c, 1.0))
            self.assertEqual(out[0].rule_id, Detector.R2)

    def test_observe_mode_only_logs(self):
        d = Detector(sampler=lambda p: 8.0, policy_mode="observe")
        self.assertEqual(burst(d, 30)[0].action, "log")

    def test_entropy(self):
        self.assertEqual(shannon_entropy(b"aaaa"), 0.0)
        self.assertGreater(shannon_entropy(os.urandom(4096)), 7.9)


class InotifyTests(unittest.TestCase):
    def test_parse_and_truncation(self):
        rec = struct.pack("iIII", 1, ino.IN_CREATE, 0, 8) + b"a.txt\0\0\0"
        self.assertEqual(list(ino.parse(rec, {1: "/r"})), [(1, ino.IN_CREATE, 0, "/r/a.txt")])
        with self.assertRaises(ValueError):
            list(ino.parse(rec[:-3], {1: "/r"}))

    def test_overflow_marks_degraded(self):
        with tempfile.TemporaryDirectory() as t:
            s = ino.InotifySensor(t)
            self.assertEqual(s.status()["health"], "limited")
            r, w = os.pipe()
            os.write(w, struct.pack("iIII", -1, ino.IN_Q_OVERFLOW, 0, 0))
            real = s.fd
            s.fd = r
            try:
                evs = s.read(0.1)
            finally:
                s.fd = real
                os.close(r); os.close(w); s.close()
            self.assertEqual(evs[0].action, "overflow")
            self.assertEqual(s.status()["health"], "degraded")
            self.assertFalse(s.status()["can_block"])

    def test_real_sensor_sees_writes_and_new_dirs(self):
        with tempfile.TemporaryDirectory() as t:
            s = ino.InotifySensor(t)
            try:
                os.mkdir(os.path.join(t, "sub"))
                s.read(0.2)  # registers watch on sub
                with open(os.path.join(t, "sub", "f"), "w") as f:
                    f.write("x")
                acts = {(e.action, os.path.basename(e.path)) for e in s.read(0.5)}
            finally:
                s.close()
            self.assertIn(("close_write", "f"), acts)


class SimulatorSafetyTests(unittest.TestCase):
    def test_refuses_unmarked_dir(self):
        with tempfile.TemporaryDirectory() as t:
            with open(os.path.join(t, "victim.txt"), "w") as f:
                f.write("keep")
            with self.assertRaises(simulator.LabError):
                simulator.run(t, "overwrite", 1)
            with open(os.path.join(t, "victim.txt")) as f:
                self.assertEqual(f.read(), "keep")

    def test_refuses_marked_dir_outside_tmp(self):
        lab = simulator.make_lab(3, 1, parent=os.path.dirname(os.path.abspath(__file__)))
        try:
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("ENDGUARD_LAB_PARENT_OK", None)
                with self.assertRaises(simulator.LabError):
                    simulator.run(lab, "overwrite", 1)
        finally:
            import shutil
            shutil.rmtree(lab)

    def test_limits(self):
        with self.assertRaises(simulator.LabError):
            simulator.make_lab(simulator.MAX_FILES + 1, 1)


class StoreTests(unittest.TestCase):
    def test_permissions_and_append_only(self):
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "a.db")
            s = Store(p)
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)
            d = burst(det(), 30)[0]
            s.add_decision(d)
            with self.assertRaises(sqlite3.DatabaseError):
                s.db.execute("UPDATE decisions SET severity='low'")
            self.assertEqual(s.decisions()[0]["decision_id"], d.decision_id)

    def test_status_without_heartbeat_is_not_healthy(self):
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "a.db")
            Store(p).add_health({"sensor": "x", "health": "limited", "causes": []})
            with mock.patch("time.time", return_value=1e12), mock.patch("builtins.print") as pr:
                cli_main(["--db", p, "status"])
            self.assertIn('"degraded"', pr.call_args[0][0])


if __name__ == "__main__":
    unittest.main()
