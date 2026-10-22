"""Offline .eml analyzer. Parses untrusted bytes only: no network, no execution, no disk writes.
Not inbox protection; absence of signals does not prove a message is legitimate."""
from __future__ import annotations

import hashlib
import io
import json
import ipaddress
import multiprocessing
import re
import threading
import unicodedata
import zipfile
from email import message_from_bytes, policy
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from urllib.parse import urlsplit

SCHEMA_VERSION = 1
MAX_BYTES = 10 * 1024 * 1024
MAX_PARTS = 200
MAX_HEADER_LINES = 2000
MAX_RESULT_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 10
MAX_URLS = 500
MAX_TEXT = 1024 * 1024
MAX_ZIP_ENTRIES = 1000
MAX_HEADER = 8 * 1024        # per header value, applied before any address/encoded-word parsing
MAX_HEADERS_KEPT = 100       # per interesting header name
MAX_HEAD = 64 * 1024         # header block parsed when the body is skipped
MAX_LINK_TEXT = 1024
THRESHOLD = 5

WEIGHTS = {
    "display_name_spoof": 3, "reply_to_mismatch": 2, "return_path_mismatch": 1,
    "link_text_mismatch": 3, "ip_literal_url": 2, "punycode_url": 2, "shortener_url": 1,
    "risky_attachment": 5, "html_attachment": 2, "double_extension": 3, "type_mismatch": 3,
    "archive_risky_content": 4, "encrypted_archive": 2, "auth_fail": 4, "urgency_language": 1,
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"}
RISKY_EXT = set("exe scr com pif bat cmd js jse vbs vbe wsf hta lnk iso img vhd one msi ps1 jar docm xlsm pptm "
                "dll chm xll cpl msc scf url reg wsh vhdx appx msix appxbundle msixbundle".split())
HTML_EXT = {"html", "htm", "svg", "shtml"}
FAIL = {"fail", "softfail", "permerror"}
DECOY_EXT = set("pdf doc docx xls xlsx ppt pptx txt csv jpg jpeg png gif zip rar html htm".split())
MAGIC = ((b"MZ", "exe"), (b"\x7fELF", "elf"), (b"PK\x03\x04", "zip"), (b"%PDF", "pdf"),
         (b"\xd0\xcf\x11\xe0", "ole"), (b"Rar!", "rar"), (b"7z\xbc\xaf", "7z"), (b"#!", "script"))
# ext -> sniffed types it may legitimately have; empty set = must not match any known magic
EXPECT = {
    "pdf": {"pdf"}, "zip": {"zip"}, "docx": {"zip"}, "xlsx": {"zip"}, "pptx": {"zip"},
    "doc": {"ole"}, "xls": {"ole"}, "ppt": {"ole"}, "exe": {"exe"}, "rar": {"rar"}, "7z": {"7z"},
    "jpg": set(), "jpeg": set(), "png": set(), "gif": set(), "txt": set(), "csv": set(),
}
URGENCY = re.compile(
    r"urgente|verifique sua conta|\bsenha\b|bloquead[ao]|verify your account|\bpassword\b|\bsuspended\b", re.I)
URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.I)
DOMAIN_RE = re.compile(r"(?<![\w.-])[a-z0-9-]+(?:\.[a-z0-9-]+)*\.([a-z]{2,24})\b", re.I)
AUTH_RE = re.compile(r"(?<![\w.-])(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
NUMERIC_LABEL = re.compile(r"0x[0-9a-f]*|\d+", re.I)   # decimal, octal (0177) and hex IPv4 forms


def _related(a: str, b: str) -> bool:
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _domain(addr: str) -> str:
    return addr.rpartition("@")[2].strip().lower() if "@" in addr else ""


def _domains_in(text: str) -> list[str]:
    out = []
    for m in DOMAIN_RE.finditer(text):
        if m.group(1).lower() not in DECOY_EXT:   # "fatura.pdf" is a filename, not a domain
            out.append(m.group(0).lower())
    return out


class _Html(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str]] = []   # (href, visible text)
        self.text: list[str] = []
        self._href: str | None = None
        self._buf: list[str] = []

    def _close(self):
        if self._href is not None:
            self.links.append((self._href, "".join(self._buf)))
        self._href, self._buf = None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._close()
            href = dict(attrs).get("href")
            if href:
                self._href = href.strip()

    def handle_endtag(self, tag):
        if tag == "a":
            self._close()

    def handle_data(self, data):
        self.text.append(data)
        if self._href is not None and sum(map(len, self._buf)) < MAX_LINK_TEXT:
            self._buf.append(data[:MAX_LINK_TEXT])

    def finish(self):
        self.close()
        self._close()


def _url_record(url: str, source: str, text: str = "") -> dict | None:
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https", "ftp") or not host:
        return None
    try:
        ipaddress.ip_address(host)
        ip = True
    except ValueError:
        ip = all(NUMERIC_LABEL.fullmatch(label) for label in host.split("."))
    return {
        "url": url[:2048], "host": host, "source": source,
        "text_host_mismatch": any(not _related(d, host) for d in _domains_in(text)),
        "ip_literal": ip,
        "punycode": not host.isascii() or any(label.startswith("xn--") for label in host.split(".")),
        "shortener": host in SHORTENERS, "scheme": parts.scheme.lower(),
    }


def _sniff(b: bytes) -> str:
    return next((name for magic, name in MAGIC if b.startswith(magic)), "unknown")


def _ext(name: str) -> str:
    n = name.strip().rstrip(". ").lower()
    return n.rpartition(".")[2] if "." in n else ""


def _segments(name: str) -> list[str]:
    # Drop control/format chars (NUL, bidi overrides), then split on NTFS stream / separator tricks ("a.exe:x").
    clean = "".join(c for c in name if unicodedata.category(c) not in ("Cc", "Cf"))
    return [seg.strip().rstrip(". ") for seg in re.split(r"[:;]", clean)]


def _exts(name: str) -> list[str]:
    return [e for e in map(_ext, _segments(name)) if e]


def _archive(payload: bytes, limits: list[str]) -> dict:
    try:
        infos = zipfile.ZipFile(io.BytesIO(payload)).infolist()   # listing only; never read/extract
    except (zipfile.BadZipFile, ValueError, OSError, NotImplementedError):
        return {"error": "unparseable"}
    truncated = len(infos) > MAX_ZIP_ENTRIES
    if truncated:
        limits.append("archive_entries")
    infos = infos[:MAX_ZIP_ENTRIES]
    names = [i.filename for i in infos]
    return {
        "entries": len(infos),
        "risky_names": [n for n in names if RISKY_EXT.intersection(_exts(n))],
        "encrypted": any(i.flag_bits & 0x1 for i in infos),
        "traversal_names": [n for n in names if _traversal(n)],
        "truncated": truncated,
    }


def _traversal(name: str) -> bool:
    n = name.replace("\\", "/")
    return n.startswith("/") or bool(re.match(r"^[A-Za-z]:", n)) or ".." in n.split("/")


def _attachment(part, payload: bytes, limits: list[str]) -> dict:
    name = (part.get_filename() or "")[:255]
    exts = _exts(name)
    ext = exts[0] if exts else ""
    sniffed = _sniff(payload[:8])
    return {
        "filename": name, "declared_type": part.get_content_type(), "sniffed_type": sniffed,
        "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
        "risky_ext": bool(RISKY_EXT.intersection(exts)),
        "double_ext": any(_ext(seg) in RISKY_EXT and _ext(seg.rpartition(".")[0]) in DECOY_EXT
                          for seg in _segments(name)),
        "type_mismatch": ext in EXPECT and sniffed != "unknown" and sniffed not in EXPECT[ext],
        "archive": _archive(payload, limits) if sniffed == "zip" else None,
    }


def _strip_comments(s: str) -> str:
    """Remove RFC 5322 comments (nested, linear scan) so text inside them cannot fake an id or a result."""
    out, depth, esc = [], 0, False
    for c in s:
        if esc:
            esc = False
        elif c == "\\" and depth:
            esc = True
        elif c == "(":
            if not depth:
                out.append(" ")
            depth += 1
        elif c == ")" and depth:
            depth -= 1
        elif not depth:
            out.append(c)
    return "".join(out)


def _auth(values: list[str], trusted_ids: frozenset[str]) -> dict:
    out = {"trusted": False, "spf": None, "dkim": None, "dmarc": None}
    trusted = {t.lower() for t in trusted_ids}
    for raw in values:   # top-most first
        value = _strip_comments(raw)
        head, _, body = value.partition(";")
        ident = head.split()
        if ident and ident[0].lower() in trusted:
            out["trusted"] = True
            for method, result in AUTH_RE.findall(body):
                m, r = method.lower(), result.lower()
                # any failing occurrence makes the method fail: a pass for another domain must not mask it
                if out[m] is None or (r in FAIL and out[m] not in FAIL):
                    out[m] = r
            break
    return out


def _decode(part, limits: list[str]) -> str:
    try:
        payload = part.get_payload(decode=True) or b""
    except Exception:
        return ""
    if len(payload) > MAX_TEXT:
        payload = payload[:MAX_TEXT]
        limits.append("text_truncated")
    try:
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _raw_headers(msg, limits: list[str]) -> dict[str, list[str]]:
    """Raw values (no policy header factory), each cut to MAX_HEADER before anything parses it."""
    out: dict[str, list[str]] = {k: [] for k in ("from", "reply-to", "return-path", "authentication-results")}
    for name, value in msg.raw_items():
        kept = out.get(name.lower())
        if kept is None:
            continue
        v = str(value)
        if len(kept) >= MAX_HEADERS_KEPT or len(v) > MAX_HEADER:
            limits.append("header_truncated")
        if len(kept) < MAX_HEADERS_KEPT:
            kept.append(v[:MAX_HEADER])
    return out


def _decode_words(s: str) -> str:
    try:
        return str(make_header(decode_header(s)))
    except Exception:
        return s


def _safe(s: str) -> str:
    return "".join("?" if unicodedata.category(c) in ("Cc", "Cf") else c for c in s[:300])


def analyze_eml(data: bytes, trusted_authserv_ids: frozenset[str] = frozenset()) -> dict:
    if len(data) > MAX_BYTES:
        raise ValueError("too large")
    errors: list[str] = []
    limits: list[str] = []
    # O(n) check on raw bytes: refuse to build a huge MIME tree at all.
    # the email parser accepts CRLF, LF and bare CR as line ends: normalize before counting
    norm = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    skip_body = (norm.count(b"\n--") > 4 * MAX_PARTS or data.lower().count(b"boundary=") > MAX_PARTS
                 or norm.split(b"\n\n", 1)[0].count(b"\n") > MAX_HEADER_LINES)
    try:
        if skip_body:
            limits.append("pre_parse_parts")
            head = norm.split(b"\n\n", 1)[0]          # normalized: bare-CR messages too
            if len(head) > MAX_HEAD or head.count(b"\n") > MAX_HEADER_LINES:
                head = b"\n".join(head[:MAX_HEAD].split(b"\n")[:MAX_HEADER_LINES])
                limits.append("header_truncated")
            msg = message_from_bytes(head, policy=policy.default)
        else:
            msg = message_from_bytes(data, policy=policy.default)
    except Exception as e:   # includes RecursionError/MemoryError: never degrade to an empty "benign" message
        errors.append(f"parse: {type(e).__name__}")
        limits.append("parse_failed")
        msg = EmailMessage()

    hdr = _raw_headers(msg, limits)
    display, addr, reply_doms, rp_dom = "", "", [], ""
    try:   # stdlib address parsing can recurse deeply on hostile (even 8 KiB) input
        display, addr = parseaddr(hdr["from"][0]) if hdr["from"] else ("", "")
        display = _decode_words(display)
        reply_doms = list(dict.fromkeys(
            d for _, a in getaddresses(hdr["reply-to"]) if (d := _domain(a))))
        rp_dom = _domain(parseaddr(hdr["return-path"][0])[1]) if hdr["return-path"] else ""
    except Exception as e:
        errors.append(f"address headers: {type(e).__name__}")
        limits.append("parse_failed")
    from_dom = _domain(addr)

    plain: list[str] = []
    html_text: list[str] = []
    urls: list[dict] = []
    attachments: list[dict] = []

    def add_url(rec):
        if rec is None:
            return
        if len(urls) >= MAX_URLS:
            limits.append("urls")
            return
        urls.append(rec)

    stack = [] if skip_body else [(msg, 0)]
    seen = 0
    while stack:
        part, depth = stack.pop()
        if seen >= MAX_PARTS:
            limits.append("max_parts")
            break
        seen += 1
        try:
            for d in part.defects[:5]:
                errors.append(f"defect: {type(d).__name__}")
            if part.is_multipart():
                if depth >= MAX_DEPTH:
                    limits.append("max_depth")
                    continue
                stack.extend((c, depth + 1) for c in reversed(list(part.iter_parts())))
                continue
            ctype = part.get_content_type()
            named = part.get_filename() or part.get_content_disposition() == "attachment"
            if named or ctype not in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True) or b""
                attachments.append(_attachment(part, payload, limits))
            elif ctype == "text/plain":
                text = _decode(part, limits)
                plain.append(text)
                for u in URL_RE.findall(text):
                    add_url(_url_record(u.rstrip(".,;:!?"), "text"))
            else:
                text = _decode(part, limits)
                h = _Html()
                h.feed(text)
                h.finish()
                html_text.append(" ".join(h.text))
                for href, label in h.links:
                    add_url(_url_record("http:" + href if href.startswith("//") else href, "html", label))
        except Exception as e:   # an aborted part means the report is partial
            errors.append(f"part: {type(e).__name__}")
            limits.append("parse_failed")

    signals: list[dict] = []

    def sig(id_: str, detail: str):
        signals.append({"id": id_, "weight": WEIGHTS[id_], "detail": _safe(detail)})

    shown = [d.lower() for d in _domains_in(display)] + [_domain(a).lower() for _, a in getaddresses([display]) if "@" in a]
    bad = next((d for d in shown if from_dom and not _related(d, from_dom)), None)
    if bad:
        sig("display_name_spoof", f"display shows {bad}, From domain is {from_dom}")
    bad = next((d for d in reply_doms if from_dom and not _related(d, from_dom)), None)
    if bad:
        sig("reply_to_mismatch", f"Reply-To {bad} vs From {from_dom}")
    if rp_dom and from_dom and not _related(rp_dom, from_dom):
        sig("return_path_mismatch", f"Return-Path {rp_dom} vs From {from_dom}")
    for flag, id_ in (("text_host_mismatch", "link_text_mismatch"), ("ip_literal", "ip_literal_url"),
                      ("punycode", "punycode_url"), ("shortener", "shortener_url")):
        u = next((u for u in urls if u[flag]), None)
        if u:
            sig(id_, u["url"])
    for flag, id_ in (("risky_ext", "risky_attachment"), ("double_ext", "double_extension"),
                      ("type_mismatch", "type_mismatch")):
        names = [a["filename"] for a in attachments if a[flag]]
        if names:
            sig(id_, ", ".join(names))
    names = [a["filename"] for a in attachments if HTML_EXT.intersection(_exts(a["filename"]))]
    if names:
        sig("html_attachment", ", ".join(names))
    arch = [a for a in attachments if a["archive"] and "error" not in a["archive"]]
    names = [a["filename"] for a in arch if a["archive"]["risky_names"] or a["archive"]["traversal_names"]]
    if names:
        sig("archive_risky_content", ", ".join(names))
    names = [a["filename"] for a in arch if a["archive"]["encrypted"]]
    if names:
        sig("encrypted_archive", ", ".join(names))
    auth = _auth(hdr["authentication-results"], trusted_authserv_ids)
    if auth["trusted"]:
        failed = [f"{k}={auth[k]}" for k in ("spf", "dkim", "dmarc") if auth[k] in FAIL]
        if failed:
            sig("auth_fail", ", ".join(failed))
    hits = sorted({m.lower() for m in URGENCY.findall(" ".join(plain + html_text))})
    if hits:
        sig("urgency_language", ", ".join(hits))

    score = sum(s["weight"] for s in signals)
    limits = list(dict.fromkeys(limits))
    return {
        "schema_version": SCHEMA_VERSION,
        "sha256": hashlib.sha256(data).hexdigest(),
        "from": {"display": display, "addr": addr, "domain": from_dom},
        "reply_to_domains": reply_doms,
        "return_path_domain": rp_dom,
        "auth": auth,
        "urls": urls,
        "attachments": attachments,
        "signals": signals,
        "score": score,
        # Not-safe by construction: a partial analysis can never read as "no strong signals".
        "verdict": "suspicious" if score >= THRESHOLD else "incomplete" if limits else "no_strong_signals",
        "limits_hit": limits,
        "parse_errors": list(dict.fromkeys(errors)),
    }


def _worker(conn, data, trusted, mem_mb):
    # results cross the boundary as JSON bytes, never pickle: a compromised child must not reach the parent
    try:
        try:
            import resource   # absent on Windows: timeout only. A resource cap, NOT a sandbox.
            lim = mem_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (lim, lim))
        except ImportError:
            pass
        out = analyze_eml(data, trusted)
    except MemoryError:
        out = {"_fail": "memory"}
    except BaseException:
        out = {"_fail": "worker_died"}
    try:
        conn.send_bytes(json.dumps(out).encode())
    except BaseException:
        pass
    finally:
        conn.close()


def analyze_eml_isolated(data: bytes, trusted_authserv_ids: frozenset[str] = frozenset(),
                         timeout_s: float = 10.0, mem_mb: int = 512) -> dict:
    """analyze_eml in a throwaway spawned process with a wall-clock timeout and an address-space cap.

    Callers that are scripts must guard their entry point with `if __name__ == "__main__":` (spawn
    re-imports __main__). Never raises except ValueError("too large"); any failure -> "incomplete".
    """
    if len(data) > MAX_BYTES:
        raise ValueError("too large")
    ctx = multiprocessing.get_context("spawn")
    parent, child = ctx.Pipe(duplex=False)
    why, result, proc, started, th = None, None, None, False, None
    try:
        proc = ctx.Process(target=_worker, args=(child, data, trusted_authserv_ids, mem_mb), daemon=True)
        proc.start()
        started = True
        child.close()
        # total deadline covers the read too: a child that stalls mid-message must not hang the parent
        box: dict = {}

        def reader():
            try:
                box["raw"] = parent.recv_bytes(MAX_RESULT_BYTES)
            except Exception:      # EOF (child killed) or oversized result
                box["err"] = True
        th = threading.Thread(target=reader, daemon=True)
        th.start()
        th.join(timeout_s)
        if th.is_alive():
            why = "timeout"
        elif "raw" in box:
            try:
                result = json.loads(box["raw"])
            except ValueError:
                why = "worker_died"
        else:
            why = "worker_died"
        if not why and not isinstance(result, dict):
            why = "worker_died"
        elif isinstance(result, dict) and "_fail" in result:
            why, result = str(result["_fail"]), None
    except Exception:            # spawn failure (EAGAIN, daemon parent, ...) -> fail closed, never raise
        why = why or "worker_died"
    finally:
        if started:
            if why:
                proc.terminate()
            proc.join(2)
            if proc.is_alive():
                proc.kill()
                proc.join()
            proc.close()
            if th is not None:
                th.join(1)    # child is dead -> reader gets EOF; never close the fd under a live reader
        parent.close()
        child.close()
    if why:
        return {"schema_version": SCHEMA_VERSION, "sha256": hashlib.sha256(data).hexdigest(),
                "from": {"display": "", "addr": "", "domain": ""}, "reply_to_domains": [],
                "return_path_domain": "", "auth": {"trusted": False, "spf": None, "dkim": None, "dmarc": None},
                "urls": [], "attachments": [], "signals": [], "score": 0,
                "verdict": "incomplete", "limits_hit": [why], "parse_errors": [f"isolation: {why}"]}
    return result
