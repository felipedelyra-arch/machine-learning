"""Record labeled SYNTHETIC event traces from the real inotify sensor (Linux) for the ML pipeline.

Each trace = one workload run in a fresh lab; events (incl. sensor-sampled entropy) saved as gzip JSONL.
Ground-truth label is per trace (malicious = safe simulator ran). Engineering data only: it does
not represent real ransomware or real user workloads (see docs/data-card-ransomware-traces.md).
Usage: python3 scripts/record_traces.py [--seeds 20] [--out data/traces]
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import random
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import run_scenarios as rs  # noqa: E402
from endguard import simulator  # noqa: E402


def sim(variant, rate, max_files):
    return lambda lab, seed: simulator.run(lab, variant, seed, rate, max_files)


def media_setup(lab, seed):
    d = os.path.join(lab, "photos")
    os.mkdir(d)
    for i in range(rs.N):
        with open(os.path.join(d, f"p{i}.jpg"), "wb") as f:
            f.write(os.urandom(8192))


def w_media_resync(lab, seed):  # sync client replaces existing photos atomically (hard negative)
    log, d = [], os.path.join(lab, "photos")
    for n in sorted(os.listdir(d)):
        p = os.path.join(d, n)
        with open(p + ".sync", "wb") as f:
            f.write(os.urandom(8192))
        os.replace(p + ".sync", p)
        rs.stamp(log, p)
    return log


def work_setup(lab, seed):     # benign files of the "mixed" family, disjoint from simulator targets
    d = os.path.join(lab, "work")
    os.mkdir(d)
    for i in range(rs.N):
        with open(os.path.join(d, f"w{i}.md"), "w") as f:
            f.write("notes alpha beta\n" * random.Random(seed * 1000 + i).randint(20, 200))


def bulk_edit_work(lab):
    d = os.path.join(lab, "work")
    for n in sorted(os.listdir(d)):
        p = os.path.join(d, n)
        with open(p) as f:
            s = f.read()
        with open(p, "w") as f:
            f.write(s.replace("alpha", "omega"))


def mixed(lab, seed, rate):     # slow attack hidden in concurrent benign text edits
    t = threading.Thread(target=bulk_edit_work, args=(lab,))
    t.start()
    log = simulator.run(lab, "overwrite", seed, rate, 40)
    t.join()
    return log


def burst_pause(lab, seed):     # test-only family: bursts below the 10 s window, separated by pauses
    log = []
    for _ in range(4):
        log += simulator.run(lab, "overwrite", seed, 200.0, 15)
        time.sleep(11)
    return log


def rotate_setup(lab, seed):
    d = os.path.join(lab, "backups")
    os.mkdir(d)
    for i in range(30):
        with open(os.path.join(d, f"old{i}.tar.gz"), "wb") as f:
            f.write(os.urandom(16384))


def w_backup_rotate(lab, seed):  # test-only hard negative: new archives written, old ones deleted
    log, d = [], os.path.join(lab, "backups")
    for i in range(30):
        with open(os.path.join(d, f"new{i}.tar.gz"), "wb") as f:
            f.write(os.urandom(16384))
        os.remove(os.path.join(d, f"old{i}.tar.gz"))
        rs.stamp(log, d)
    return log


def grid(fam: str, seed: int):
    """Deterministic per-(family, seed) parameters -> (workload, setup, n_files, params)."""
    rng = random.Random(f"{fam}:{seed}")
    if fam == "sim_burst_pause":         # must precede the generic sim_* branch
        return burst_pause, None, rs.N, {}
    if fam.startswith("sim_"):
        variant = fam[4:]
        if variant == "slow":
            rate, mf = rng.uniform(1.0, 2.5), rng.randint(12, 25)
            return sim("overwrite", rate, mf), None, rs.N, {"rate": round(rate, 2), "max_files": mf}
        if variant == "mixed":
            rate = rng.choice([3.0, 5.0, 10.0])
            return (lambda lab, s: mixed(lab, s, rate)), work_setup, rs.N, {"rate": rate}
        rate, n = rng.choice([30, 100, 300, 1000]), rng.choice([60, 200, 500])
        mf = rng.choice([None, None, rng.randint(25, 60)])   # sometimes stops early (partial run)
        return sim(variant, rate, mf), None, n, {"rate": rate, "n_files": n, "max_files": mf}
    if fam == "benign_backup_rotate":
        return w_backup_rotate, rotate_setup, 20, {}
    if fam == "benign_media_resync":
        return w_media_resync, media_setup, 20, {}
    return rs.SCENARIOS[fam][0], None, rs.N, {}


TEST_ONLY = ["sim_burst_pause", "benign_backup_rotate"]   # v2: never used for training
MALICIOUS = ["sim_burst_pause", "sim_overwrite", "sim_write_new_delete", "sim_rename_overwrite", "sim_tmp_rename_replace",
             "sim_slow", "sim_mixed"]
BENIGN = ["benign_backup_rotate", "benign_copy_compressed", "benign_bulk_text_edit", "benign_rm_tree", "benign_zip_archive",
          "benign_tar_backup", "benign_unzip_media", "benign_editor_atomic_save", "benign_gzip_inplace",
          "benign_media_resync"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=20)
    ap.add_argument("--seed-start", type=int, default=0)
    ap.add_argument("--out", default="data/traces")
    ap.add_argument("--families", nargs="*")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    manifest_path = os.path.join(a.out, "manifest.json")
    manifest = json.load(open(manifest_path)) if os.path.exists(manifest_path) else {"traces": []}
    done = {t["id"] for t in manifest["traces"]}
    for fam in a.families or [f for f in MALICIOUS + BENIGN if f not in TEST_ONLY]:
        for seed in range(a.seed_start, a.seed_start + a.seeds):
            tid = f"{fam}-{seed:03d}"
            if tid in done:
                continue
            work, setup, n, params = grid(fam, seed)
            events = []
            r = rs.run_one(fam, seed, work=work, expect="alert", n=n, setup=setup, events_out=events)
            path = os.path.join(a.out, tid + ".jsonl.gz")
            with gzip.open(path, "wt") as f:
                for ev in events:
                    f.write(json.dumps(ev.to_dict()) + "\n")
            with open(path, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            manifest["traces"].append({
                "id": tid, "family": fam, "label": int(fam in MALICIOUS), "seed": seed, "params": params,
                "n_events": len(events), "n_ops": r["ops_total"], "t0": r["t0"],
                "op_ts": [ts for ts, _ in r["op_log"]], "sensor_health": r["sensor"]["health"],
                "rule_r1_alerted": r["alerted"], "sha256": digest})
            with open(manifest_path + ".tmp", "w") as f:
                json.dump(manifest, f)
            os.replace(manifest_path + ".tmp", manifest_path)   # resumable, crash-safe
            print(tid, len(events), "events", "R1" if r["alerted"] else "-", flush=True)


if __name__ == "__main__":
    main()
