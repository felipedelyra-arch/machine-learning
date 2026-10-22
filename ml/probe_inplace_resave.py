"""EXPLORATORY probe (not part of the pre-registered evaluation): benign in-place high-entropy saves."""
import os, sys, numpy as np
sys.path.insert(0, "scripts"); sys.path.insert(0, "ml"); sys.path.insert(0, ".")
import run_scenarios as rs, train_eval_v2 as v2
from endguard.ml_model import vectorize
from endguard.rules import Detector, Thresholds
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

def setup(lab, seed):
    os.mkdir(os.path.join(lab, "media"))
    for i in range(40):
        with open(os.path.join(lab, "media", f"v{i}.jpg"), "wb") as f: f.write(os.urandom(65536))

def resave(k):            # photo editor / DB / office app: rewrite k existing compressed files in place
    def w(lab, seed):
        log = []
        for i in range(k):
            p = os.path.join(lab, "media", f"v{i}.jpg")
            with open(p, "r+b") as f: f.write(os.urandom(65536))
            rs.stamp(log, p)
        return log
    return w

if __name__ == "__main__":
    tv = v2.load("data/traces"); train = [t for t in tv if t["seed"] <= 13]; val = [t for t in tv if t["seed"] >= 14]
    Xtr = np.vstack([t["X"] for t in train if len(t["X"])]); ytr = np.concatenate([np.full(len(t["X"]), t["label"]) for t in train])
    sc = StandardScaler().fit(Xtr); lr = LogisticRegression(class_weight="balanced", C=0.1, max_iter=5000, random_state=0).fit(sc.transform(Xtr), ytr)
    raw = lambda ts_: np.array([float(lr.decision_function(sc.transform(t["X"])).max()) for t in ts_])
    yv = np.array([t["label"] for t in val]); platt = LogisticRegression(random_state=0).fit(raw(val).reshape(-1, 1), yv)
    thr = 0.593
    for k in (1, 2, 3, 5, 10):
        hits = 0
        for seed in range(3):
            evs = []; rs.run_one(f"probe{k}", seed, work=resave(k), expect="no_alert", n=20, setup=setup, events_out=evs)
            d10, d60 = Detector(), Detector(Thresholds(window_s=60.0)); X = []
            for e in evs:
                d10.feed(e); d60.feed(e); X.append(vectorize(d10.features()) + vectorize(d60.features()))
            if X:
                s = platt.predict_proba(lr.decision_function(sc.transform(np.array(X))).reshape(-1, 1))[:, 1].max()
                hits += s >= thr
        print(f"benign in-place resave of {k:2d} existing high-entropy files: LR alerts in {hits}/3 runs")
