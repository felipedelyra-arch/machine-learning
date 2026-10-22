"""Read-only curses view of the audit DB. Observation only: shows what was recorded, never acts."""
from __future__ import annotations

import curses
import os
import time
import unicodedata

from .status import effective_health
from .store import Store

STYLE_OF = {"limited": "warn", "degraded": "bad", "disabled": "bad"}
EMPTY = "Nenhum alerta registrado (isso não prova ausência de ameaça)"
FOOTER = "↑/↓ ou k/j selecionam · r recarrega · q sai"


def clean(v) -> str:
    # DB content is untrusted: neutralise control/format chars (ESC, CR/LF, bidi) and lone surrogates
    return "".join("?" if unicodedata.category(c) in ("Cc", "Cf", "Cs") else c for c in str(v))


def build_view(health: dict, decisions: list[dict], selected: int, width: int) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    add = lambda t, s="normal": out.append((clean(t)[:max(width - 1, 0)], s))  # noqa: E731
    h = health.get("health", "disabled")
    add("endguard — observação/detecção (não bloqueia)", "title")
    add(f"Sensor: {h}", STYLE_OF.get(h, "bad"))   # unknown state is shown as bad, never as OK
    if health.get("error"):
        add(f"Erro ao ler o DB: {health['error']}", "bad")
    add(f"Causas: {', '.join(map(str, health.get('causes', []))) or '-'}")
    add(f"Diretórios vigiados: {health.get('watched_dirs', '-')}   Overflows: {health.get('overflows', '-')}")
    add("Pode bloquear: não", "warn")
    add("Modo atual: observação/alerta — nenhuma ação automática; recuperação depende de backup")
    add("")
    add("Decisões recentes", "title")
    if not decisions:
        add(EMPTY)
        add("")
        add(FOOTER)
        return out
    sel = min(max(selected, 0), len(decisions) - 1)
    for i, d in enumerate(decisions):
        hhmmss = time.strftime("%H:%M:%S", time.localtime(d.get("ts", 0)))
        add(f"{'>' if i == sel else ' '} {hhmmss} {d.get('severity', '?'):<6} {d.get('rule_id', '?')} {d.get('summary', '')}",
            "selected" if i == sel else "normal")
    d = decisions[sel]
    add("")
    add("Detalhes", "title")
    add(f"Resumo: {d.get('summary', '')}")
    add("Features: " + (" ".join(f"{k}={v}" for k, v in (d.get("features") or {}).items()) or "-"))
    add(f"Incerteza: {d.get('uncertainty', '-')}")
    add(f"Política: {d.get('policy_mode', '-')} / ação: {d.get('action', '-')}")
    add(f"Evidências: {len(d.get('evidence') or [])}   decision_id: {d.get('decision_id', '-')}")
    add("")
    add(FOOTER)
    return out


def load(db: str, limit: int = 50) -> tuple[dict, list[dict]]:
    try:
        health = effective_health(db)   # never creates the file
        # Store() would create a missing DB, so only open it when it exists
        return health, (Store(db, readonly=True).decisions(limit) if os.path.exists(db) else [])
    except Exception as e:   # noqa: BLE001 - the TUI must not crash on a bad DB
        return {"health": "disabled", "causes": [], "error": type(e).__name__}, []


def _attrs(color: bool) -> dict:
    if color:
        curses.use_default_colors()
        for i, c in enumerate((curses.COLOR_YELLOW, curses.COLOR_RED, curses.COLOR_CYAN), 1):
            curses.init_pair(i, c, -1)
        return {"warn": curses.color_pair(1) | curses.A_BOLD, "bad": curses.color_pair(2) | curses.A_BOLD,
                "title": curses.color_pair(3) | curses.A_BOLD, "ok": 0, "selected": curses.A_REVERSE, "normal": 0}
    return {"ok": 0, "warn": curses.A_BOLD, "bad": curses.A_BOLD, "title": curses.A_BOLD,
            "selected": curses.A_REVERSE, "normal": 0}


def _loop(stdscr, db: str) -> None:
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    attrs = _attrs(curses.has_colors())
    stdscr.timeout(2000)
    health, decisions = load(db)
    sel = 0
    while True:
        h, w = stdscr.getmaxyx()
        stdscr.erase()
        try:
            lines = [("terminal pequeno", "bad")] if h < 10 or w < 40 else build_view(health, decisions, sel, w)
        except Exception as e:      # malformed rows from a tampered DB must not kill the view
            lines = [(f"erro ao exibir decisões: {type(e).__name__}", "bad")]
        for y, (t, s) in enumerate(lines[:h]):
            try:
                stdscr.addstr(y, 0, t, attrs.get(s, 0))
            except (curses.error, UnicodeError):
                pass
        stdscr.refresh()
        k = stdscr.getch()
        if k in (ord("q"), 27):
            return
        if k in (curses.KEY_DOWN, ord("j")):
            sel = min(sel + 1, max(len(decisions) - 1, 0))
        elif k in (curses.KEY_UP, ord("k")):
            sel = max(sel - 1, 0)
        elif k in (ord("r"), -1):   # -1 = 2 s timeout: periodic reload
            health, decisions = load(db)
            sel = min(sel, max(len(decisions) - 1, 0))


def run(db_path: str) -> None:
    try:
        curses.wrapper(_loop, db_path)
    except KeyboardInterrupt:
        pass
