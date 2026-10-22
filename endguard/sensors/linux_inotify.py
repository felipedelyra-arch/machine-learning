"""Linux inotify sensor (unprivileged, OBSERVATIONAL ONLY).

inotify cannot block operations and does not report which process acted. Coverage is "limited" by
design; queue overflow or watch-limit exhaustion flips health to "degraded" with the cause.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
import select
import struct
import time

from ..schema import FileEvent

IN_MODIFY, IN_CLOSE_WRITE, IN_MOVED_FROM, IN_MOVED_TO = 0x2, 0x8, 0x40, 0x80
IN_CREATE, IN_DELETE, IN_DELETE_SELF, IN_Q_OVERFLOW, IN_IGNORED, IN_ISDIR = 0x100, 0x200, 0x400, 0x4000, 0x8000, 0x40000000
IN_NONBLOCK, IN_CLOEXEC = 0o4000, 0o2000000
MASK = IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_DELETE_SELF
HDR = struct.Struct("iIII")
MAP = {IN_CLOSE_WRITE: "close_write", IN_MOVED_FROM: "rename_from", IN_MOVED_TO: "rename_to",
       IN_CREATE: "create", IN_DELETE: "delete"}
QUALITY = ("no_process_attribution", "no_kernel_timestamp")


def parse(buf: bytes, wd_paths: dict[int, str]):
    """Yield (wd, mask, cookie, full_path) from a raw inotify read buffer. Pure; unit-testable."""
    off = 0
    while off + HDR.size <= len(buf):
        wd, mask, cookie, ln = HDR.unpack_from(buf, off)
        off += HDR.size
        if off + ln > len(buf):
            raise ValueError("truncated inotify record")
        name = buf[off:off + ln].rstrip(b"\0").decode("utf-8", "surrogateescape")
        off += ln
        base = wd_paths.get(wd)
        yield wd, mask, cookie, (os.path.join(base, name) if base and name else base)


class InotifySensor:
    name = "linux.inotify"

    def __init__(self, root: str, max_dirs: int = 50_000):
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        self._add = libc.inotify_add_watch
        self._add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        self.fd = libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self.fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1 failed")
        self.root = os.path.realpath(root)
        self.max_dirs = max_dirs
        self.wds: dict[int, str] = {}
        self.health, self.causes = "initializing", []
        self.dropped = 0
        self._watch_tree(self.root)
        if self.health == "initializing":
            self.health = "limited"   # observational sensor without process attribution

    def _degrade(self, cause: str):
        self.health = "degraded"
        if cause not in self.causes:
            self.causes.append(cause)

    def _watch(self, path: str):
        if len(self.wds) >= self.max_dirs:
            return self._degrade(f"max_dirs {self.max_dirs} reached; subtree unwatched")
        wd = self._add(self.fd, os.fsencode(path), MASK)
        if wd < 0:
            err = ctypes.get_errno()
            if err == errno.ENOSPC:
                return self._degrade("fs.inotify.max_user_watches exhausted")
            if err not in (errno.ENOENT, errno.ENOTDIR):
                self._degrade(f"add_watch {path}: {os.strerror(err)}")
            return
        self.wds[wd] = path

    def _watch_tree(self, top: str):
        self._watch(top)
        for d, dirs, _ in os.walk(top, onerror=lambda e: self._degrade(f"walk: {e}")):
            # never descend through symlinks (os.walk default followlinks=False)
            for sub in dirs:
                self._watch(os.path.join(d, sub))

    def read(self, timeout: float = 0.5) -> list[FileEvent]:
        r, _, _ = select.select([self.fd], [], [], timeout)
        if not r:
            return []
        try:
            buf = os.read(self.fd, 65536)
        except BlockingIOError:
            return []
        now, out = time.time(), []
        for wd, mask, cookie, path in parse(buf, self.wds):
            if mask & IN_Q_OVERFLOW:
                self.dropped += 1
                self._degrade("kernel queue overflow: events lost")
                out.append(FileEvent("overflow", self.root, self.name, "linux", ts_received=now, quality=QUALITY))
                continue
            if mask & IN_IGNORED:
                self.wds.pop(wd, None)
                continue
            if path is None:
                continue
            if mask & IN_ISDIR:
                if mask & (IN_CREATE | IN_MOVED_TO):
                    self._watch_tree(path)   # new dir: files created before the watch lands are missed (race)
                continue
            act = next((a for bit, a in MAP.items() if mask & bit), None)
            if act is None:
                continue
            dev = ino = None
            q = QUALITY
            if act not in ("delete", "rename_from"):
                try:
                    st = os.lstat(path)
                    dev, ino = st.st_dev, st.st_ino
                except OSError:
                    q = QUALITY + ("stat_failed",)
            out.append(FileEvent(act, path, self.name, "linux", ts_received=now, dev=dev, inode=ino,
                                 cookie=cookie, quality=q))
        return out

    def status(self) -> dict:
        return {"sensor": self.name, "health": self.health, "causes": list(self.causes),
                "watched_dirs": len(self.wds), "overflows": self.dropped, "can_block": False}

    def close(self):
        os.close(self.fd)
