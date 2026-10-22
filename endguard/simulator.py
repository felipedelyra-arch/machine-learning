"""Safe lab simulator of ransomware-like FILE BEHAVIOR.

Safety contract: it only touches files it created itself inside a fresh directory it created under
the system temp dir, marked with LAB_MARKER. Payloads are os.urandom bytes (no real crypto, no keys,
nothing recoverable or extortable). No propagation, evasion, process tampering or backup access.
Hard limits on file count, bytes and duration.
"""
from __future__ import annotations

import os
import random
import tempfile
import time

LAB_MARKER = ".endguard-lab"
MAX_FILES, MAX_BYTES, MAX_SECONDS = 2000, 64 * 1024, 120
VARIANTS = ("overwrite", "write_new_delete", "rename_overwrite")


class LabError(RuntimeError):
    pass


def make_lab(n_files: int, seed: int, parent: str | None = None) -> str:
    if not 0 < n_files <= MAX_FILES:
        raise LabError(f"n_files must be 1..{MAX_FILES}")
    lab = tempfile.mkdtemp(prefix="endguard-lab-", dir=parent)
    with open(os.path.join(lab, LAB_MARKER), "w") as f:
        f.write(f"synthetic lab seed={seed}\n")
    rng = random.Random(seed)
    words = "alpha beta gamma delta report invoice budget meeting notes plan".split()
    for i in range(n_files):
        sub = os.path.join(lab, f"d{i % 7}")
        os.makedirs(sub, exist_ok=True)
        with open(os.path.join(sub, f"doc{i:04d}.txt"), "w") as f:
            f.write(" ".join(rng.choice(words) for _ in range(rng.randint(200, 800))))
    return lab


def _lab_files(lab: str) -> list[str]:
    real = os.path.realpath(lab)
    if not os.path.isfile(os.path.join(real, LAB_MARKER)):
        raise LabError("refusing: directory has no lab marker")
    if os.path.dirname(real) != os.path.realpath(tempfile.gettempdir()) and not os.environ.get("ENDGUARD_LAB_PARENT_OK"):
        raise LabError("refusing: lab must live directly under the system temp dir")
    files = []
    for d, _, names in os.walk(real):
        files += [os.path.join(d, n) for n in names if n.endswith(".txt") and not os.path.islink(os.path.join(d, n))]
    return sorted(files)


def run(lab: str, variant: str, seed: int, rate_per_s: float = 200.0, max_files: int | None = None) -> list[tuple[float, str]]:
    """Damage the lab's own synthetic files. Returns [(ts, path)] of completed ops for damage accounting."""
    if variant not in VARIANTS:
        raise LabError(f"variant must be one of {VARIANTS}")
    files = _lab_files(lab)[:max_files]
    rng = random.Random(seed)
    rng.shuffle(files)
    t0, log = time.monotonic(), []
    for p in files:
        if time.monotonic() - t0 > MAX_SECONDS:
            break
        size = min(os.path.getsize(p) or 1, MAX_BYTES)
        blob = os.urandom(size)
        if variant == "overwrite":
            with open(p, "r+b") as f:
                f.write(blob)
                f.truncate()
        elif variant == "write_new_delete":
            with open(p + ".locked", "wb") as f:
                f.write(blob)
            os.remove(p)
        else:
            q = p + ".locked"
            os.rename(p, q)
            with open(q, "r+b") as f:
                f.write(blob)
                f.truncate()
        log.append((time.time(), p))
        if rate_per_s:
            time.sleep(1.0 / rate_per_s)
    return log
