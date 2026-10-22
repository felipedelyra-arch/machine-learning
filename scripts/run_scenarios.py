"""Scenario battery: real inotify sensor + detector against safe simulator and benign workloads.

One run -> structured evidence (JSON + Markdown) for every scenario x seed. Synthetic data only:
results exercise the pipeline, they do NOT demonstrate efficacy against real ransomware.
Usage: python3 scripts/run_scenarios.py [--seeds 1 2 3] [--out evidence]
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import platform
import random
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from endguard import simulator  # noqa: E402
from endguard.rules import Detector  # noqa: E402
from endguard.sensors.linux_inotify import InotifySensor  # noqa: E402

N = 200


def txt_files(lab):
    return sorted(os.path.join(d, n) for d, _, ns in os.walk(lab) for n in ns if n.endswith(".txt"))


def stamp(log, p):
    log.append((time.time(), p))


def w_copy_compressed(lab, seed):     # like copying photos/videos in: many NEW high-entropy files
    log, dst = [], os.path.join(lab, "incoming"); os.makedirs(dst)
    for i in range(N):
        p = os.path.join(dst, f"img{i}.jpg")
        with open(p, "wb") as f:
            f.write(os.urandom(8192))
        stamp(log, p)
    return log


def w_bulk_text_edit(lab, seed):      # search/replace across a codebase: overwrites, low entropy
    log = []
    for p in txt_files(lab):
        with open(p) as f:
            s = f.read()
        with open(p, "w") as f:
            f.write(s.replace("alpha", "omega"))
        stamp(log, p)
    return log


def w_rm_tree(lab, seed):
    log = []
    for p in txt_files(lab):
        os.remove(p); stamp(log, p)
    return log


def w_zip_archive(lab, seed):
    with zipfile.ZipFile(os.path.join(lab, "backup.zip"), "w", zipfile.ZIP_DEFLATED) as z:
        for p in txt_files(lab):
            z.write(p, os.path.relpath(p, lab))
    return [(time.time(), "backup.zip")]


def w_tar_backup(lab, seed):
    with tarfile.open(os.path.join(lab, "backup.tar.gz"), "w:gz") as t:
        t.add(os.path.join(lab, "d0"), arcname="d0")
    return [(time.time(), "backup.tar.gz")]


def w_unzip(lab, seed):               # extracting an archive of compressed media: NEW files
    zp = os.path.join(lab, "media.zip")
    with zipfile.ZipFile(zp, "w", zipfile.ZIP_STORED) as z:
        for i in range(N):
            z.writestr(f"m/{i}.png", os.urandom(8192))
    with zipfile.ZipFile(zp) as z:
        z.extractall(os.path.join(lab, "out"))
    return [(time.time(), zp)]


def w_gzip_inplace(lab, seed):        # `gzip -r`: new compressed file + delete original (KNOWN FP)
    log = []
    for p in txt_files(lab):
        with open(p, "rb") as f, gzip.open(p + ".gz", "wb") as g:
            shutil.copyfileobj(f, g)
        os.remove(p); stamp(log, p)
    return log


def sim(variant, rate=200.0, max_files=None):
    return lambda lab, seed: simulator.run(lab, variant, seed, rate, max_files)


SCENARIOS = {
    # name: (workload, expectation)  expectation in {alert, no_alert, known_fp, known_miss}
    "sim_overwrite": (sim("overwrite"), "alert"),
    "sim_write_new_delete": (sim("write_new_delete"), "alert"),
    "sim_rename_overwrite": (sim("rename_overwrite"), "alert"),
    "sim_slow_below_threshold": (sim("overwrite", rate=1.5, max_files=18), "known_miss"),
    "benign_copy_compressed": (w_copy_compressed, "no_alert"),
    "benign_bulk_text_edit": (w_bulk_text_edit, "no_alert"),
    "benign_rm_tree": (w_rm_tree, "no_alert"),
    "benign_zip_archive": (w_zip_archive, "no_alert"),
    "benign_tar_backup": (w_tar_backup, "no_alert"),
    "benign_unzip_media": (w_unzip, "no_alert"),
    "benign_gzip_inplace": (w_gzip_inplace, "known_fp"),
}


def run_one(name, seed):
    work, expect = SCENARIOS[name]
    lab = simulator.make_lab(N, seed)
    sensor = InotifySensor(lab)
    det = Detector(policy_mode="alert")
    decisions, stop = [], threading.Event()

    def pump():
        while not stop.is_set():
            for ev in sensor.read(0.1):
                decisions.extend(det.feed(ev))
        for ev in sensor.read(0.3):       # final drain
            decisions.extend(det.feed(ev))

    th = threading.Thread(target=pump); th.start()
    t0 = time.time()
    try:
        log = work(lab, seed)
        time.sleep(1.0)
    finally:
        stop.set(); th.join()
        st = sensor.status(); sensor.close()
        shutil.rmtree(lab, ignore_errors=True)
    r1 = [d for d in decisions if d.rule_id == Detector.R1]
    first = r1[0] if r1 else None
    alerted = first is not None
    ok = {"alert": alerted, "known_fp": alerted, "no_alert": not alerted, "known_miss": not alerted}[expect]
    return {
        "scenario": name, "seed": seed, "expectation": expect, "alerted": alerted, "pass": ok,
        "ops_total": len(log),
        "ops_before_alert": sum(1 for ts, _ in log if first and ts < first.ts) if first else None,
        "seconds_to_alert": round(first.ts - t0, 3) if first else None,
        "features_at_alert": first.features if first else None,
        "sensor": st,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    ap.add_argument("--out", default="evidence")
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args()
    names = a.only or list(SCENARIOS)
    results = [run_one(n, s) for n in names for s in a.seeds]
    try:
        rev = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    except OSError:
        rev = ""
    meta = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "git": rev or "uncommitted", "python": sys.version.split()[0],
            "platform": platform.platform(), "machine": platform.machine(), "cpus": os.cpu_count(),
            "seeds": a.seeds, "files_per_lab": N, "data": "synthetic only"}
    os.makedirs(a.out, exist_ok=True)
    tag = time.strftime("%Y%m%d-%H%M%S")
    with open(os.path.join(a.out, f"scenarios-{tag}.json"), "w") as f:
        json.dump({"meta": meta, "results": results}, f, indent=1)
    lines = [f"# Scenario run {tag}", "", "```", json.dumps(meta, indent=1), "```", "",
             "| scenario | seed | expect | alerted | pass | ops before alert / total | s to alert | sensor |",
             "|---|---|---|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r['scenario']} | {r['seed']} | {r['expectation']} | {r['alerted']} | "
                     f"{'PASS' if r['pass'] else 'FAIL'} | {r['ops_before_alert']} / {r['ops_total']} | "
                     f"{r['seconds_to_alert']} | {r['sensor']['health']} |")
    with open(os.path.join(a.out, f"scenarios-{tag}.md"), "w") as f:
        f.write("\n".join(lines) + "\n")
    fails = [r for r in results if not r["pass"]]
    print(f"{len(results) - len(fails)}/{len(results)} pass -> {a.out}/scenarios-{tag}.md")
    for r in fails:
        print("FAIL", r["scenario"], r["seed"], r["features_at_alert"])
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
