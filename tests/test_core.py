import json
import shutil
import os
import sqlite3
import stat
import struct
import tempfile
import unittest
from unittest import mock

from endguard import simulator
from endguard.cli import main as cli_main
from endguard.features import sample_entropy, shannon_entropy
from endguard.rules import Detector, Thresholds
from endguard.schema import FileEvent, SchemaError
from endguard.sensors import linux_inotify as ino
from endguard.store import Store


def ev(action, path, ts, **kw):
    return FileEvent(action, path, "test", "linux", ts_received=ts, **kw)


def det(high=True, **kw):
    return Detector(Thresholds(), sampler=lambda e: 7.99 if high else 4.0, policy_mode="alert", **kw)


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
                    {"action": "create", "path": "/x", "sensor": "s", "platform": "linux", "quality": 5},
                    {"action": "create", "path": "/x", "sensor": "s", "platform": "linux", "ts_event": "1"},
                    {"action": "create", "path": "/x", "sensor": "s", "platform": "linux", "event_id": [1]},
                    {"action": "create", "path": "/x", "sensor": "s", "platform": "linux", "inode": -1},
                    {"action": "create", "path": "/x", "sensor": "s", "platform": "linux", "cookie": True},
                    {"action": "create", "path": "/x", "sensor": "s", "platform": "linux", "ts_received": float("nan")},
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

    def test_atomic_replace_evasion_detected(self):
        d, out = det(), []
        for i in range(30):
            t = 100 + i * 0.01
            out += d.feed(ev("create", f"/lab/.tmp{i}", t))
            out += d.feed(ev("close_write", f"/lab/.tmp{i}", t))
            out += d.feed(ev("rename_from", f"/lab/.tmp{i}", t, cookie=i + 1))
            out += d.feed(ev("rename_to", f"/lab/f{i}", t, cookie=i + 1))
        self.assertEqual([x.rule_id for x in out], [Detector.R1])

    def test_hardlink_alias_is_not_new(self):
        d, out = det(), []
        for i in range(30):
            t = 100 + i * 0.01
            out += d.feed(ev("create", f"/lab/f{i}.l", t, dev=1, inode=i, quality=("multi_link",)))
            out += d.feed(ev("close_write", f"/lab/f{i}.l", t, dev=1, inode=i))
        self.assertEqual([x.rule_id for x in out], [Detector.R1])

    def test_phased_rename_then_overwrite_detected(self):
        d, out = det(), []
        for i in range(30):
            out += d.feed(ev("rename_from", f"/lab/f{i}", 100 + i * 0.01, cookie=i + 1))
            out += d.feed(ev("rename_to", f"/lab/f{i}.x", 100 + i * 0.01, cookie=i + 1))
        self.assertEqual(out, [])                     # renames alone: no entropy signal
        for i in range(30):
            out += d.feed(ev("close_write", f"/lab/f{i}.x", 115 + i * 0.01, dev=1, inode=i))
        self.assertEqual([x.rule_id for x in out], [Detector.R1])

    def test_new_file_renamed_stays_new(self):
        d = det()
        for i in range(30):
            t = 100 + i * 0.01
            d.feed(ev("create", f"/lab/n{i}.part", t, dev=1, inode=i))
            d.feed(ev("rename_from", f"/lab/n{i}.part", t, cookie=i + 1))
            d.feed(ev("rename_to", f"/lab/n{i}", t, cookie=i + 1))
            d.feed(ev("close_write", f"/lab/n{i}", t, dev=1, inode=i))
        f = d.features()
        self.assertEqual((f["write_new"], f["overwrite"], f["rename_existing"]), (30, 0, 0))

    def test_created_files_expire_to_preexisting(self):
        d = det()
        for i in range(30):
            d.feed(ev("create", f"/lab/f{i}", 100.0))
        self.assertEqual(len(burst(d, 30, t0=500.0)), 1)   # encrypted in place long after creation

    def test_unsampled_writes_excluded_from_ratio(self):
        d = Detector(sampler=lambda e: None if e.path.endswith("x") else 8.0)
        for i in range(30):
            d.feed(ev("close_write", f"/lab/f{i}x", 100 + i * 0.001))
        burst(d, 25, t0=100.1, step=0.001)
        self.assertEqual(d.features()["high_entropy_ratio"], 1.0)

    def test_default_sampler_never_reads_disk(self):
        d = Detector()
        with mock.patch("os.open", side_effect=AssertionError("disk read")):
            for i in range(30):
                d.feed(ev("close_write", f"/etc/f{i}", 100 + i * 0.01, content_entropy=8.0))
        self.assertEqual(d.features()["high_entropy_writes"], 30)

    def test_overflow_is_reported_as_coverage_gap(self):
        d = det()
        d.feed(ev("overflow", "/lab", 99.0))
        self.assertIn("events were lost", burst(d, 30)[0].uncertainty)

    def test_canary_atomic_replace(self):
        with tempfile.TemporaryDirectory() as t:
            c = os.path.join(t, "canary.docx")
            open(c, "w").close()
            out = det(canaries=[c]).feed(ev("rename_to", c, 1.0, cookie=9))
            self.assertEqual(out[0].rule_id, Detector.R2)

    def test_canary(self):
        with tempfile.TemporaryDirectory() as t:
            c = os.path.join(t, "canary.docx")
            open(c, "w").close()
            out = det(canaries=[c]).feed(ev("close_write", c, 1.0))
            self.assertEqual(out[0].rule_id, Detector.R2)

    def test_observe_mode_only_logs(self):
        d = Detector(sampler=lambda e: 8.0, policy_mode="observe")
        self.assertEqual(burst(d, 30)[0].action, "log")

    def test_entropy(self):
        with tempfile.TemporaryDirectory() as t:
            fifo = os.path.join(t, "p")
            os.mkfifo(fifo)
            self.assertIsNone(sample_entropy(fifo))
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

    def _events(self, setup, act):
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "f")
            setup(p)
            s = ino.InotifySensor(t)
            try:
                act(p)
                return s, s.read(0.3)
            finally:
                s.close()

    def test_open_for_write_without_writing_is_flagged_and_ignored_if_low_entropy(self):
        def setup(p):
            with open(p, "w") as f:
                f.write("plain text " * 100)
        _, evs = self._events(setup, lambda p: os.close(os.open(p, os.O_RDWR)))
        self.assertEqual([e.action for e in evs], ["close_write"])
        self.assertIn("no_modify_seen", evs[0].quality)
        self.assertEqual(Detector().feed(evs[0]), [])
        d = Detector()
        d.feed(evs[0])
        self.assertEqual(d.features()["overwrite"], 0)

    def test_mmap_write_is_not_dropped(self):
        import mmap

        def setup(p):
            with open(p, "wb") as f:
                f.write(b"a" * 8192)

        def act(p):
            with open(p, "r+b") as f, mmap.mmap(f.fileno(), 0) as m:
                m[:] = os.urandom(8192)
                m.flush()
        _, evs = self._events(setup, act)
        cw = [e for e in evs if e.action == "close_write"]
        self.assertEqual(len(cw), 1)
        d = Detector()
        d.feed(cw[0])
        self.assertEqual(d.features()["overwrite"], 1)   # high entropy -> counted despite no IN_MODIFY

    def test_modify_tracking_cleared_on_unlink(self):
        def act(p):
            fd = os.open(p, os.O_RDWR)
            os.write(fd, b"x")
            os.unlink(p)
            os.close(fd)
        s, _ = self._events(lambda p: open(p, "w").close(), act)
        self.assertEqual(s.modified, set())

    def test_modify_flood_degrades_not_blinds(self):
        with tempfile.TemporaryDirectory() as t:
            s = ino.InotifySensor(t)
            try:
                with mock.patch.object(ino, "MAX_MODIFIED", 3):
                    fds = [os.open(os.path.join(t, f"f{i}"), os.O_CREAT | os.O_WRONLY) for i in range(5)]
                    for fd in fds:
                        os.write(fd, b"x")     # modified, still open -> tracked entries pile up
                    for fd in fds:
                        os.close(fd)
                    evs = s.read(0.3)
                self.assertEqual(s.status()["health"], "degraded")
                self.assertIn("close_write", [e.action for e in evs])
            finally:
                s.close()

    def test_dir_symlink_not_watched(self):
        with tempfile.TemporaryDirectory() as t, tempfile.TemporaryDirectory() as outside:
            os.symlink(outside, os.path.join(t, "link"))
            s = ino.InotifySensor(t)
            try:
                self.assertNotIn(outside, s.wds.values())
                with open(os.path.join(outside, "f"), "w") as f:
                    f.write("x")
                self.assertEqual(s.read(0.3), [])
            finally:
                s.close()


class SimulatorSafetyTests(unittest.TestCase):
    def test_refuses_unmarked_dir(self):
        with tempfile.TemporaryDirectory() as t:
            with open(os.path.join(t, "victim.txt"), "w") as f:
                f.write("keep")
            with self.assertRaises(simulator.LabError):
                simulator.run(t, "overwrite", 1)
            with open(os.path.join(t, "victim.txt")) as f:
                self.assertEqual(f.read(), "keep")

    def test_refuses_forged_marker_dir(self):
        with tempfile.TemporaryDirectory() as t:
            open(os.path.join(t, simulator.LAB_MARKER), "w").close()
            with self.assertRaises(simulator.LabError):
                simulator.run(t, "overwrite", 1)

    def test_refuses_lab_outside_tmp(self):
        here = os.path.dirname(os.path.abspath(__file__))
        lab = simulator.make_lab(3, 1, parent=here)
        try:
            with self.assertRaises(simulator.LabError):
                simulator.run(lab, "overwrite", 1)
        finally:
            shutil.rmtree(lab)

    def _swap_test(self, swap):
        lab = simulator.make_lab(1, 1)
        with tempfile.NamedTemporaryFile("w", delete=False) as out:
            out.write("keep")
        try:
            victim = next(iter(simulator._LABS[lab]))
            os.remove(victim)
            swap(out.name, victim)
            with self.assertRaises((simulator.LabError, OSError)):
                simulator.run(lab, "overwrite", 1, rate_per_s=0)
            with open(out.name) as f:
                self.assertEqual(f.read(), "keep")
        finally:
            os.remove(out.name)
            shutil.rmtree(lab)

    def test_hardlink_swap_refused(self):
        self._swap_test(os.link)

    def test_symlink_swap_refused(self):
        self._swap_test(os.symlink)

    def test_locked_name_symlink_not_followed(self):
        for v in ("write_new_delete", "rename_overwrite"):
            lab = simulator.make_lab(1, 1)
            with tempfile.NamedTemporaryFile("w", delete=False) as out:
                out.write("keep")
            try:
                os.symlink(out.name, next(iter(simulator._LABS[lab])) + ".locked")
                with self.assertRaises((simulator.LabError, OSError), msg=v):
                    simulator.run(lab, v, 1, rate_per_s=0)
                with open(out.name) as f:
                    self.assertEqual(f.read(), "keep", msg=v)
            finally:
                os.remove(out.name)
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
            for sql in ("UPDATE decisions SET severity='low'", "DELETE FROM decisions",
                        "UPDATE health SET body='{}'", "DELETE FROM health"):
                s.add_health({"health": "limited", "causes": []})
                with self.assertRaises(sqlite3.DatabaseError, msg=sql):
                    s.db.execute(sql)
            self.assertEqual(s.decisions()[0]["decision_id"], d.decision_id)

    def test_existing_db_permissions_tightened(self):
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "a.db")
            open(p, "w").close()
            os.chmod(p, 0o644)
            Store(p)
            self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)

    def test_status_without_heartbeat_is_not_healthy(self):
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "a.db")
            Store(p).add_health({"sensor": "x", "health": "limited", "causes": []})
            with mock.patch("time.time", return_value=1e12), mock.patch("builtins.print") as pr:
                cli_main(["--db", p, "status"])
            self.assertIn('"degraded"', pr.call_args[0][0])

    def _status(self, health, now=None):
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "a.db")
            Store(p).add_health(health)
            with mock.patch("builtins.print") as pr:
                if now is not None:
                    with mock.patch("time.time", return_value=now):
                        cli_main(["--db", p, "status"])
                else:
                    cli_main(["--db", p, "status"])
            return json.loads(pr.call_args[0][0])

    def test_status_future_heartbeat_is_degraded(self):
        self.assertEqual(self._status({"health": "limited", "causes": []}, now=0.0)["health"], "degraded")

    def test_status_dead_pid_is_degraded(self):
        import subprocess
        pr = subprocess.Popen(["true"]); pr.wait()
        self.assertEqual(self._status({"health": "limited", "causes": [], "pid": pr.pid})["health"], "degraded")
        self.assertEqual(self._status({"health": "limited", "causes": [], "pid": os.getpid()})["health"], "limited")


if __name__ == "__main__":
    unittest.main()
