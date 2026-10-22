"""ML v2 (pre-registered in docs/data-card-ransomware-traces.md, section v2).

Train/val = all v1 traces (seed split 0-13 / 14-19); test = freshly recorded v2 traces incl. two
never-trained families. LR on 10 s + 60 s window features, Platt-calibrated at trace level on val;
threshold = lowest with val benign FPR <= 10%. Ensemble = R1 OR LR. Promotion rule fixed in advance.
Usage: .venv/bin/python ml/train_eval_v2.py
"""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import sys
import time

import numpy as np
from sklearn import __version__ as SKV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from endguard.ml_model import FEATURES, vectorize  # noqa: E402
from endguard.rules import Detector, Thresholds  # noqa: E402
from endguard.schema import FileEvent  # noqa: E402

SEED, MAX_FPR = 0, 0.10
FEATS = [f"{k}@10s" for k in FEATURES] + [f"{k}@60s" for k in FEATURES]


def load(root: str) -> list[dict]:
    man, out = json.load(open(os.path.join(root, "manifest.json"))), []
    for t in man["traces"]:
        p = os.path.join(root, t["id"] + ".jsonl.gz")
        if hashlib.sha256(open(p, "rb").read()).hexdigest() != t["sha256"]:
            sys.exit(f"hash mismatch {t['id']}")
        d10, d60 = Detector(policy_mode="alert"), Detector(Thresholds(window_s=60.0), policy_mode="alert")
        X, ts, r1 = [], [], None
        with gzip.open(p, "rt") as f:
            for line in f:
                ev = FileEvent.from_dict(json.loads(line))
                if r1 is None and any(d.rule_id == Detector.R1 for d in d10.feed(ev)):
                    r1 = ev.ts_received
                d60.feed(ev)        # R1 at 60 s window is NOT used as a rule, only as features
                X.append(vectorize(d10.features()) + vectorize(d60.features()))
                ts.append(ev.ts_received)
        out.append({**t, "X": np.array(X, dtype=float).reshape(-1, len(FEATS)), "ts": np.array(ts), "r1": r1})
    return out


def recall(y, p):
    return float(((p == 1) & (y == 1)).sum() / max(1, (y == 1).sum()))


def metrics(name, y, pred, traces, first, score=None):
    tp, fp = int(((pred == 1) & (y == 1)).sum()), int(((pred == 1) & (y == 0)).sum())
    fn, tn = int(((pred == 0) & (y == 1)).sum()), int(((pred == 0) & (y == 0)).sum())
    fam, ops = {}, {}
    for t, p, ft in zip(traces, pred, first):
        d = fam.setdefault(t["family"], [0, 0]); d[0] += int(p); d[1] += 1
        if t["label"] and p and ft is not None:
            ops.setdefault(t["family"], []).append(sum(1 for o in t["op_ts"] if o < ft))
    r = {"model": name, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
         "precision": round(tp / (tp + fp), 3) if tp + fp else None, "recall": round(recall(y, pred), 3),
         "fpr": round(fp / max(1, fp + tn), 3),
         "by_family": {k: f"{v[0]}/{v[1]}" for k, v in sorted(fam.items())},
         "ops_before_detection_median": {k: float(np.median(v)) for k, v in sorted(ops.items())}}
    if score is not None:
        r["pr_auc"] = round(average_precision_score(y, score), 3)
        r["brier"] = round(brier_score_loss(y, score), 3)
        bins = np.minimum((score * 5).astype(int), 4)
        r["reliability"] = [{"bin": f"{b/5:.1f}-{(b+1)/5:.1f}", "n": int((bins == b).sum()),
                             "mean_pred": round(float(score[bins == b].mean()), 3),
                             "frac_pos": round(float(y[bins == b].mean()), 3)} for b in range(5) if (bins == b).any()]
    return r


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--test-dir", default="data/traces-v2-test")
    ap.add_argument("--out-dir", default="evidence")
    a = ap.parse_args()
    tv, test = load("data/traces"), load(a.test_dir)
    train = [t for t in tv if t["seed"] <= 13]
    val = [t for t in tv if t["seed"] >= 14]
    Xtr = np.vstack([t["X"] for t in train if len(t["X"])])
    ytr = np.concatenate([np.full(len(t["X"]), t["label"]) for t in train])
    sc = StandardScaler().fit(Xtr)
    lr = LogisticRegression(class_weight="balanced", C=0.1, max_iter=5000, random_state=SEED).fit(sc.transform(Xtr), ytr)

    def raw(ts_):     # trace score = max window decision function (logit), before calibration
        return np.array([float(lr.decision_function(sc.transform(t["X"])).max()) if len(t["X"]) else -50.0
                         for t in ts_])

    yv = np.array([t["label"] for t in val])
    platt = LogisticRegression(random_state=SEED).fit(raw(val).reshape(-1, 1), yv)   # val only
    cal = lambda s: platt.predict_proba(s.reshape(-1, 1))[:, 1]  # noqa: E731
    sv = cal(raw(val))
    cands = sorted(set(sv))
    thr = next(c for c in cands if ((sv >= c) & (yv == 0)).sum() / max(1, (yv == 0).sum()) <= MAX_FPR)
    # ---- frozen: thresholds/calibration fixed above; test touched once below ----
    yt = np.array([t["label"] for t in test])
    st = cal(raw(test))
    p_lr = (st >= thr).astype(int)
    p_r1 = np.array([int(t["r1"] is not None) for t in test])
    p_en = p_lr | p_r1

    def first_lr(t):
        if not len(t["X"]):
            return None
        s = cal(lr.decision_function(sc.transform(t["X"])))
        i = np.nonzero(s >= thr)[0]
        return float(t["ts"][i[0]]) if len(i) else None
    f_lr = [first_lr(t) for t in test]
    f_r1 = [t["r1"] for t in test]
    f_en = [min([x for x in (a, b) if x is not None], default=None) for a, b in zip(f_lr, f_r1)]

    rng, gains = np.random.default_rng(SEED), []
    for _ in range(2000):                         # paired bootstrap over test traces
        i = rng.integers(0, len(yt), len(yt))
        gains.append(recall(yt[i], p_en[i]) - recall(yt[i], p_r1[i]))
    gain_ci = [round(float(np.percentile(gains, 2.5)), 3), round(float(np.percentile(gains, 97.5)), 3)]
    res = {"rule_R1": metrics("rule_R1", yt, p_r1, test, f_r1),
           "lr_v2": metrics("lr_v2", yt, p_lr, test, f_lr, st),
           "ensemble_R1_or_lr": metrics("ensemble", yt, p_en, test, f_en)}
    n_ben = int((yt == 0).sum())
    promote = gain_ci[0] > 0 and res["ensemble_R1_or_lr"]["fp"] <= res["rule_R1"]["fp"] + 0.05 * n_ben
    meta = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "sklearn": SKV, "threshold_calibrated": round(float(thr), 4),
            "sizes": {"train": len(train), "val": len(val), "test": len(test), "test_pos": int(yt.sum())},
            "recall_gain_ensemble_vs_R1_ci95": gain_ci, "promotion_rule_met": bool(promote),
            "coef": dict(zip(FEATS, [round(c, 3) for c in lr.coef_[0]]))}
    out = os.path.join(a.out_dir, f"ml-eval-v2-{time.strftime('%Y%m%d-%H%M%S')}.json")
    with open(out, "w") as f:
        json.dump({"meta": meta, "results": res}, f, indent=1)
    print(json.dumps({"meta": meta, "results": res}, indent=1))


if __name__ == "__main__":
    main()
