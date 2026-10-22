"""Train/evaluate ransomware-behavior baselines on recorded synthetic traces (pre-registered split).

Compares: R1 rule (as shipped) vs logistic regression (supervised) vs IsolationForest (benign-only).
Unit of evaluation = trace (max score over its windows). Threshold picked on validation only, then
frozen; test evaluated once. Exports LR as JSON (no pickle). Synthetic data: no real-world efficacy claim.
Usage: .venv/bin/python ml/train_eval.py [--traces data/traces] [--out evidence]
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import math
import os
import sys
import time

import numpy as np
from sklearn import __version__ as SKV
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, confusion_matrix, f1_score
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from endguard.ml_model import FEATURES, vectorize  # noqa: E402
from endguard.rules import Detector  # noqa: E402
from endguard.schema import FileEvent  # noqa: E402

HELDOUT = {"sim_tmp_rename_replace", "benign_media_resync", "benign_editor_atomic_save"}
SEED = 0


def split_of(t: dict) -> str:
    if t["family"] in HELDOUT:
        return "test"
    return "train" if t["seed"] <= 11 else "val" if t["seed"] <= 15 else "test"


def replay(path: str):
    """-> (X [n_events, n_feat], event ts, R1 first-alert ts or None). Features of the shipped detector."""
    det, X, ts, r1 = Detector(policy_mode="alert"), [], [], None
    with gzip.open(path, "rt") as f:
        for line in f:
            ev = FileEvent.from_dict(json.loads(line))
            out = det.feed(ev)
            if r1 is None and any(d.rule_id == Detector.R1 for d in out):
                r1 = ev.ts_received
            X.append(vectorize(det.features()))
            ts.append(ev.ts_received)
    return np.array(X, dtype=float).reshape(-1, len(FEATURES)), np.array(ts), r1


def ci(fn, y, s, n=1000):
    """Bootstrap 95% CI over traces."""
    rng, vals = np.random.default_rng(SEED), []
    for _ in range(n):
        i = rng.integers(0, len(y), len(y))
        if len(set(y[i])) < 2:
            continue
        vals.append(fn(y[i], s[i]))
    return [round(float(np.percentile(vals, 2.5)), 3), round(float(np.percentile(vals, 97.5)), 3)]


def report(name, y, score, thr, traces, first_ts):
    pred = (score >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else float("nan")
    fam, ops_before = {}, {}
    for t, p, ft in zip(traces, pred, first_ts):
        d = fam.setdefault(t["family"], [0, 0])
        d[0] += int(p); d[1] += 1
        if t["label"] and p and ft is not None:
            ops_before.setdefault(t["family"], []).append(sum(1 for o in t["op_ts"] if o < ft))
    r = {"model": name, "threshold": thr, "n": int(len(y)), "positives": int(y.sum()),
         "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn),
         "precision": round(prec, 3), "recall": round(rec, 3),
         "f1": round(f1_score(y, pred, zero_division=0), 3),
         "f1_ci95": ci(lambda a, b: f1_score(a, (b >= thr).astype(int), zero_division=0), y, score),
         "recall_ci95": ci(lambda a, b: ((b >= thr) & (a == 1)).sum() / max(1, (a == 1).sum()), y, score),
         "alert_rate_by_family": {k: f"{v[0]}/{v[1]}" for k, v in sorted(fam.items())},
         "ops_before_detection_median": {k: float(np.median(v)) for k, v in sorted(ops_before.items())}}
    if len(set(score)) > 2:
        r["pr_auc"] = round(average_precision_score(y, score), 3)
        r["pr_auc_ci95"] = ci(average_precision_score, y, score)
    return r


def best_threshold(y, s):
    cands = np.unique(s)
    f1s = [f1_score(y, (s >= c).astype(int), zero_division=0) for c in cands]
    return float(cands[int(np.argmax(f1s))])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--traces", default="data/traces")
    ap.add_argument("--out", default="evidence")
    a = ap.parse_args()
    man = json.load(open(os.path.join(a.traces, "manifest.json")))
    traces, seen = [], set()
    for t in man["traces"]:
        p = os.path.join(a.traces, t["id"] + ".jsonl.gz")
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()
        if h != t["sha256"]:
            sys.exit(f"hash mismatch {t['id']}")
        if h in seen:
            continue            # exact duplicate trace
        seen.add(h)
        X, ts, r1 = replay(p)
        traces.append({**t, "X": X, "ts": ts, "r1": r1, "split": split_of(t)})
    by = {s: [t for t in traces if t["split"] == s] for s in ("train", "val", "test")}

    # supervised rows: every window snapshot, label = trace label (noisy early windows; see data card)
    Xtr = np.vstack([t["X"] for t in by["train"] if len(t["X"])])
    ytr = np.concatenate([np.full(len(t["X"]), t["label"]) for t in by["train"]])
    scaler = StandardScaler().fit(Xtr)                         # fit on train only
    lr = LogisticRegression(class_weight="balanced", max_iter=2000, random_state=SEED).fit(scaler.transform(Xtr), ytr)
    iso = IsolationForest(n_estimators=200, random_state=SEED).fit(
        scaler.transform(np.vstack([t["X"] for t in by["train"] if not t["label"] and len(t["X"])])))

    def trace_scores(ts_, model):
        out, first = [], []
        for t in ts_:
            if not len(t["X"]):
                out.append(0.0); first.append(None); continue
            z = scaler.transform(t["X"])
            s = lr.predict_proba(z)[:, 1] if model == "lr" else -iso.score_samples(z)
            out.append(float(s.max())); first.append(s)
        return np.array(out), first

    def first_cross(series, thr, t):
        if series is None:
            return None
        idx = np.nonzero(series >= thr)[0]
        return float(t["ts"][idx[0]]) if len(idx) else None

    results = {}
    yv = np.array([t["label"] for t in by["val"]])
    yt = np.array([t["label"] for t in by["test"]])
    # R1 rule: binary, threshold fixed by design
    r1t = np.array([1.0 if t["r1"] is not None else 0.0 for t in by["test"]])
    results["rule_R1"] = report("rule_R1", yt, r1t, 1.0, by["test"], [t["r1"] for t in by["test"]])
    for m in ("lr", "iso"):
        sv, _ = trace_scores(by["val"], m)
        thr = best_threshold(yv, sv)                            # chosen on validation only, then frozen
        st, series = trace_scores(by["test"], m)
        first = [first_cross(s, thr, t) for s, t in zip(series, by["test"])]
        results[m] = report(m, yt, st, thr, by["test"], first)
        if m == "lr":
            results[m]["brier_trace_level"] = round(brier_score_loss(yt, st), 3)
            results[m]["note"] = "max-over-windows probability is not calibrated per trace"
        else:
            results[m]["note"] = "anomaly score, not a probability"

    model = {"kind": "logistic_regression", "version": 1, "features": FEATURES,
             "mean": scaler.mean_.tolist(), "scale": scaler.scale_.tolist(),
             "coef": lr.coef_[0].tolist(), "intercept": float(lr.intercept_[0]),
             "threshold": results["lr"]["threshold"], "trained_on": hashlib.sha256(
                 json.dumps(sorted(t["sha256"] for t in by["train"])).encode()).hexdigest(),
             "sklearn": SKV, "data": "synthetic traces v1; engineering baseline, efficacy NOT demonstrated"}
    os.makedirs("models", exist_ok=True)
    blob = json.dumps(model, indent=1).encode()
    with open("models/ransomware-lr-v1.json", "wb") as f:
        f.write(blob)
    meta = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "sklearn": SKV, "numpy": np.__version__,
            "split_sizes": {k: [len(v), sum(t["label"] for t in v)] for k, v in by.items()},
            "heldout_families": sorted(HELDOUT), "train_rows": int(len(ytr)),
            "model_sha256": hashlib.sha256(blob).hexdigest(),
            "coef": dict(zip(FEATURES, [round(c, 3) for c in lr.coef_[0]]))}
    out = os.path.join(a.out, f"ml-eval-{time.strftime('%Y%m%d-%H%M%S')}.json")
    with open(out, "w") as f:
        json.dump({"meta": meta, "results": results}, f, indent=1)
    print(json.dumps({"meta": meta, "results": results}, indent=1))


if __name__ == "__main__":
    main()
