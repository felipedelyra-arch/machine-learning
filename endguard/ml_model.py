"""Local model inference (stdlib). Models are plain JSON, never pickle; every field is validated.

Loading requires the expected sha256 (pinned by whoever deploys it). A pinned hash proves integrity
relative to that pin, NOT origin: signed promotion with anti-downgrade is still pending.
"""
from __future__ import annotations

import hashlib
import json
import math
import os

FEATURES = ["overwrite", "write_new", "rename_existing", "replace", "delete_existing",
            "high_entropy_writes", "unsampled_writes", "high_entropy_ratio"]
MAX_MODEL_BYTES = 64 * 1024


class ModelError(ValueError):
    pass


def vectorize(f: dict) -> list[float]:
    # counts are heavy-tailed -> log1p; the ratio is already in [0, 1]
    return [math.log1p(f[k]) if k != "high_entropy_ratio" else float(f[k]) for k in FEATURES]


def _finite_list(v, n: int, name: str) -> list[float]:
    if not isinstance(v, list) or len(v) != n or not all(
            isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) for x in v):
        raise ModelError(f"bad {name}")
    return [float(x) for x in v]


class LogisticModel:
    def __init__(self, d: dict):
        if d.get("kind") != "logistic_regression" or d.get("version") != 1:
            raise ModelError("unsupported model kind/version")
        if d.get("features") != FEATURES:
            raise ModelError("feature contract mismatch")
        n = len(FEATURES)
        self.mean = _finite_list(d.get("mean"), n, "mean")
        self.scale = _finite_list(d.get("scale"), n, "scale")
        if any(s <= 0 for s in self.scale):
            raise ModelError("bad scale")
        self.coef = _finite_list(d.get("coef"), n, "coef")
        self.intercept, self.threshold = _finite_list([d.get("intercept"), d.get("threshold")], 2, "scalars")
        if not 0.0 <= self.threshold <= 1.0:
            raise ModelError("bad threshold")

    def score(self, features: dict) -> float:
        z = self.intercept + sum(c * (x - m) / s for c, x, m, s in
                                 zip(self.coef, vectorize(features), self.mean, self.scale))
        z = max(-60.0, min(60.0, z))
        return 1.0 / (1.0 + math.exp(-z))


def load_model(path: str, expected_sha256: str) -> LogisticModel:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        blob = f.read(MAX_MODEL_BYTES + 1)
    if len(blob) > MAX_MODEL_BYTES:
        raise ModelError("model too large")
    if hashlib.sha256(blob).hexdigest() != expected_sha256:
        raise ModelError("model hash does not match pin")
    try:
        d = json.loads(blob)
    except ValueError as e:
        raise ModelError("model is not JSON") from e
    if not isinstance(d, dict):
        raise ModelError("model must be an object")
    return LogisticModel(d)
