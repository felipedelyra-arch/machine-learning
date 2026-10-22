"""Safe lab simulator of ransomware-like FILE BEHAVIOR.

Safety contract: it only touches regular files that THIS PROCESS created via make_lab (tracked by
(dev, inode) in memory, never trusted from disk), inside a fresh 0700 dir under the system temp dir.
Every open is O_NOFOLLOW, re-checked by inode, single-link and owner; new files are O_EXCL.
Payloads are os.urandom bytes (no real crypto, no keys). No propagation, evasion, process tampering
or backup access. Hard limits on file count, bytes and duration.
"""
from __future__ import annotations

import os
import random
import stat
import tempfile
import time

LAB_MARKER = ".endguard-lab"
MAX_FILES, MAX_BYTES, MAX_SECONDS = 2000, 64 * 1024, 120
VARIANTS = ("overwrite", "write_new_delete", "rename_overwrite", "tmp_rename_replace")
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_LABS: dict[str, dict[str, tuple[int, int]]] = {}   # realpath(lab) -> {path: (dev, ino)} created by us


class LabError(RuntimeError):
    pass


def _create(path: str, data: bytes) -> tuple[int, int]:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        st = os.fstat(fd)
        return st.st_dev, st.st_ino
    finally:
        os.close(fd)


def make_lab(n_files: int, seed: int, parent: str | None = None) -> str:
    if not 0 < n_files <= MAX_FILES:
        raise LabError(f"n_files must be 1..{MAX_FILES}")
    lab = os.path.realpath(tempfile.mkdtemp(prefix="endguard-lab-", dir=parent))   # mode 0700
    _create(os.path.join(lab, LAB_MARKER), f"synthetic lab seed={seed}\n".encode())
    rng = random.Random(seed)
    words = "alpha beta gamma delta report invoice budget meeting notes plan".split()
    owned = {}
    for i in range(n_files):
        sub = os.path.join(lab, f"d{i % 7}")
        if not os.path.isdir(sub):
            os.mkdir(sub, 0o700)
        p = os.path.join(sub, f"doc{i:04d}.txt")
        owned[p] = _create(p, " ".join(rng.choice(words) for _ in range(rng.randint(200, 800))).encode())
    _LABS[lab] = owned
    return lab


def _lab_files(lab: str) -> dict[str, tuple[int, int]]:
    real = os.path.realpath(lab)
    if os.path.dirname(real) != os.path.realpath(tempfile.gettempdir()):
        raise LabError("refusing: lab must live directly under the system temp dir")
    if real not in _LABS:
        raise LabError("refusing: lab was not created by this process")
    return _LABS[real]


def _open_owned(path: str, ident: tuple[int, int], write: bool) -> int:
    fd = os.open(path, (os.O_RDWR if write else os.O_RDONLY) | NOFOLLOW)   # raises ELOOP on a swapped-in symlink
    st = os.fstat(fd)
    if (st.st_dev, st.st_ino) != ident or st.st_nlink != 1 or st.st_uid != os.geteuid() \
            or not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise LabError(f"refusing: {path} is no longer the file we created")
    return fd


def _overwrite(fd: int, blob: bytes):
    os.lseek(fd, 0, os.SEEK_SET)
    os.write(fd, blob)
    os.ftruncate(fd, len(blob))


def run(lab: str, variant: str, seed: int, rate_per_s: float = 200.0, max_files: int | None = None) -> list[tuple[float, str]]:
    """Damage the lab's own synthetic files. Returns [(ts, path)] of completed ops for damage accounting."""
    if variant not in VARIANTS:
        raise LabError(f"variant must be one of {VARIANTS}")
    owned = _lab_files(lab)
    files = sorted(owned)[:max_files]
    rng = random.Random(seed)
    rng.shuffle(files)
    t0, log = time.monotonic(), []
    for p in files:
        if time.monotonic() - t0 > MAX_SECONDS:
            break
        ident = owned.pop(p)
        fd = _open_owned(p, ident, write=variant in ("overwrite", "rename_overwrite"))
        try:
            blob = os.urandom(min(os.fstat(fd).st_size or 1, MAX_BYTES))
            if variant == "overwrite":
                _overwrite(fd, blob)
            elif variant == "write_new_delete":
                _create(p + ".locked", blob)
                os.remove(p)   # fd still verifies p was ours; lab dir is 0700 so no swap by other users
            elif variant == "tmp_rename_replace":
                tmp = os.path.join(os.path.dirname(p), f".~{os.path.basename(p)}.tmp")
                _create(tmp, blob)
                os.rename(tmp, p)   # replaces the verified original; tmp was created O_EXCL by us
            else:
                q = p + ".locked"
                if os.path.lexists(q):
                    raise LabError(f"refusing: {q} exists")
                os.rename(p, q)
                _overwrite(fd, blob)   # write through the verified fd, not the new name
        finally:
            os.close(fd)
        log.append((time.time(), p))
        if rate_per_s:
            time.sleep(1.0 / rate_per_s)
    return log
