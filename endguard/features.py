"""Content features. Reads are bounded, regular-files-only and never follow a final symlink."""
from __future__ import annotations

import math
import os
import stat
from collections import Counter

SAMPLE_BYTES = 4096
HIGH_ENTROPY = 7.2      # bits/byte over a 4 KiB sample; ciphertext/compressed ~7.9+


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def sample_entropy(path: str) -> float | None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None     # FIFOs/devices: never block or crash the sensor
        return shannon_entropy(os.read(fd, SAMPLE_BYTES))
    except OSError:
        return None
    finally:
        os.close(fd)
