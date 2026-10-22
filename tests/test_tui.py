import os
import tempfile
import unittest

from endguard import tui

D = {"decision_id": "abc", "ts": 0, "rule_id": "R1", "severity": "high", "summary": "boom",
     "features": {"n": 3}, "evidence": ["e1", "e2"], "uncertainty": "low", "policy_mode": "observe", "action": "alert"}


def text(v):
    return "\n".join(t for t, _ in v)


class TuiViewTest(unittest.TestCase):
    def test_health_styles_and_no_protected(self):
        for h, style in (("limited", "warn"), ("degraded", "bad"), ("disabled", "bad")):
            v = tui.build_view({"health": h, "causes": ["x"]}, [D], 0, 100)
            self.assertIn((f"Sensor: {h}", style), v)
            self.assertNotIn("protegido", text(v).lower())
            self.assertIn("Pode bloquear: não", text(v))

    def test_empty(self):
        self.assertIn(tui.EMPTY, text(tui.build_view({"health": "limited"}, [], 0, 100)))

    def test_error_line(self):
        v = tui.build_view({"health": "disabled", "error": "OperationalError"}, [], 0, 100)
        self.assertIn(("Erro ao ler o DB: OperationalError", "bad"), v)

    def test_sanitized(self):
        d = {**D, "summary": "a\x1b[31mb‮c\nd", "features": {"p\r": "‮"}}
        t = text(tui.build_view({"health": "limited"}, [d], 0, 200))
        for bad in ("\x1b", "‮", "\r"):
            self.assertNotIn(bad, t)
        self.assertIn("a?[31mb?c?d", t)

    def test_truncate(self):
        v = tui.build_view({"health": "limited"}, [D], 0, 20)
        self.assertTrue(all(len(t) <= 19 for t, _ in v))

    def test_selected_out_of_range(self):
        for s in (-5, 99):
            v = tui.build_view({"health": "limited"}, [D], s, 100)
            self.assertEqual(sum(st == "selected" for _, st in v), 1)

    def test_missing_db_not_created(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "x.db")
            h, ds = tui.load(p)
            self.assertEqual((h["health"], ds), ("disabled", []))
            self.assertFalse(os.path.exists(p))


if __name__ == "__main__":
    unittest.main()


class ReviewHardening(unittest.TestCase):
    def test_clean_replaces_lone_surrogates(self):
        self.assertEqual(tui.clean("a\udcffb"), "a?b")

    def test_readonly_store_never_creates_or_locks(self):
        import os, sqlite3, tempfile
        from endguard.store import Store
        with tempfile.TemporaryDirectory() as t:
            p = os.path.join(t, "a.db")
            with self.assertRaises(sqlite3.OperationalError):
                Store(p, readonly=True)
            self.assertFalse(os.path.exists(p))
            w = Store(p)
            w.add_health({"health": "limited", "causes": []})
            w.db.execute("BEGIN IMMEDIATE")     # writer holds the lock
            self.assertEqual(Store(p, readonly=True).last_health()["health"], "limited")
            w.db.execute("ROLLBACK")
