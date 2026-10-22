import hashlib
import json
import os
import tempfile
import unittest

from endguard.ml_model import FEATURES, LogisticModel, ModelError, load_model

GOOD = {"kind": "logistic_regression", "version": 1, "features": FEATURES, "mean": [0.0] * 8,
        "scale": [1.0] * 8, "coef": [1.0] + [0.0] * 7, "intercept": 0.0, "threshold": 0.5}
ZERO = {k: 0 for k in FEATURES}


def write(t, obj, raw=None):
    p = os.path.join(t, "m.json")
    blob = raw if raw is not None else json.dumps(obj).encode()
    with open(p, "wb") as f:
        f.write(blob)
    return p, hashlib.sha256(blob).hexdigest()


class ModelLoadTests(unittest.TestCase):
    def test_loads_and_scores(self):
        with tempfile.TemporaryDirectory() as t:
            m = load_model(*write(t, GOOD))
            self.assertAlmostEqual(m.score(ZERO), 0.5)
            self.assertGreater(m.score({**ZERO, "overwrite": 100}), 0.99)

    def test_rejects_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as t:
            p, _ = write(t, GOOD)
            with self.assertRaises(ModelError):
                load_model(p, "0" * 64)

    def test_rejects_bad_fields(self):
        for bad in [{**GOOD, "coef": [float("nan")] * 8}, {**GOOD, "coef": [1.0] * 7},
                    {**GOOD, "scale": [0.0] * 8}, {**GOOD, "features": FEATURES[::-1]},
                    {**GOOD, "kind": "pickle"}, {**GOOD, "threshold": 2.0}, {**GOOD, "coef": [True] * 8}]:
            with self.assertRaises(ModelError, msg=bad):
                LogisticModel(bad)

    def test_rejects_non_json_large_and_symlink(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(ModelError):
                load_model(*write(t, None, raw=b"\x80\x04pickle"))
            with self.assertRaises(ModelError):
                load_model(*write(t, None, raw=b" " * (64 * 1024 + 1)))
            p, h = write(t, GOOD)
            os.symlink(p, os.path.join(t, "link.json"))
            with self.assertRaises(OSError):
                load_model(os.path.join(t, "link.json"), h)


if __name__ == "__main__":
    unittest.main()
