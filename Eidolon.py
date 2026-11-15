#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Eidolon v3.1.0 — SPECTRAL CORE
================================
Operative terminal framework.

Core lives here. Modules live in ./modules/*.py
Each module must expose:
    NAME     : str
    OPTIONS  : dict
    run(opts): callable
Optional:
    DESCRIPTION, AUTHOR, VERSION, CATEGORY, on_load()

Module type (v3.1.0)
--------------------
Modules may declare a module-level variable:

    MODULE_TYPE = "auxiliary" | "generic" | "exploit"

If MODULE_TYPE is absent (or unrecognised), the module is treated as
"generic".  auxiliary and generic modules have no special behaviour —
the type is purely a label.

Exploit metadata (v3.1.0)
-------------------------
Exploit modules may additionally declare:

    VULNERABILITIES = ["CVE-2021-44228", ...]   # or single str
    CVSS            = 9.8                       # float, optional
    SEVERITY        = "critical"                # optional override

Session system (v3.1.0)
-----------------------
When an *exploit* module enters a subshell, Eidolon automatically
opens a session record.  The record is closed when the subshell
returns to Eidolon (back / exit).  Sessions are listed read-only via
the `sessions` command.  There is intentionally no kill/terminate
command for sessions.

Module API (v3.1.0):
    EIDOLON_GLOBALS  : dict        — shared globals (setg)
    EIDOLON_SHELL    : Eidolon     — shell instance for subshell control
"""

from __future__ import annotations

import os
import re
import sys
import cmd
import copy
import time
import shlex
import traceback
import importlib.util

VERSION      = "3.1.0"
CODENAME     = "SPECTRAL_CORE"
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
MODULES_DIR  = os.path.join(BASE_DIR, "modules")
SESSION_T0   = time.time()


# ────────────────────────────────────────────────────────────
#  Module type constants
# ────────────────────────────────────────────────────────────
MODULE_TYPE_AUXILIARY = "auxiliary"
MODULE_TYPE_GENERIC   = "generic"
MODULE_TYPE_EXPLOIT   = "exploit"

VALID_MODULE_TYPES = {
    MODULE_TYPE_AUXILIARY,
    MODULE_TYPE_GENERIC,
    MODULE_TYPE_EXPLOIT,
}

_MODULE_TYPE_ALIASES = {
    "aux":       MODULE_TYPE_AUXILIARY,
    "auxiliary": MODULE_TYPE_AUXILIARY,
    "generic":   MODULE_TYPE_GENERIC,
    "public":    MODULE_TYPE_GENERIC,
    "exploit":   MODULE_TYPE_EXPLOIT,
    "exp":       MODULE_TYPE_EXPLOIT,
}


def _module_type(mod) -> str:
    """Return the module type, defaulting to 'generic'."""
    raw = str(getattr(mod, "MODULE_TYPE", "") or "").strip().lower()
    return _MODULE_TYPE_ALIASES.get(raw, MODULE_TYPE_GENERIC)


def _module_vulns(mod) -> list:
    """Return exploit vulnerabilities as a list of strings (empty if none)."""
    v = (getattr(mod, "VULNERABILITIES", None)
         or getattr(mod, "VULNERABILITY", None)
         or getattr(mod, "CVE", None))
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    try:
        return [str(x) for x in v]
    except TypeError:
        return [str(v)]


def _module_cvss(mod):
    """Return the CVSS score as float, or None."""
    v = getattr(mod, "CVSS", None)
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _cvss_severity(score):
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def _cvss_color(score):
    if score is None:
        return None
    if score >= 9.0:
        return "red"
    if score >= 7.0:
        return "crimson"
    if score >= 4.0:
        return "yellow"
    if score > 0.0:
        return "lime"
    return "gray"


# ────────────────────────────────────────────────────────────
#  Readline-safe ANSI handling
# ────────────────────────────────────────────────────────────
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def rl_prompt_safe(s: str) -> str:
    """Wrap ANSI escape sequences in \\001...\\002 so readline ignores their width."""
    return _ANSI_RE.sub(lambda m: f"\001{m.group(0)}\002", s)


# ────────────────────────────────────────────────────────────
#  Colors
# ────────────────────────────────────────────────────────────
class C:
    RESET    = "\033[0m"
    BOLD     = "\033[1m"
    DIM      = "\033[2m"

    RED      = "\033[38;2;255;60;100m"
    CRIMSON  = "\033[38;2;200;30;60m"
    GREEN    = "\033[38;2;0;255;140m"
    LIME     = "\033[38;2;140;255;80m"
    YELLOW   = "\033[38;2;255;210;60m"
    GOLD     = "\033[38;2;220;170;30m"
    CYAN     = "\033[38;2;0;240;255m"
    ELECTRIC = "\033[38;2;100;200;255m"
    BLUE     = "\033[38;2;80;130;255m"
    PURPLE   = "\033[38;2;170;90;255m"
    VIOLET   = "\033[38;2;130;60;220m"
    PINK     = "\033[38;2;255;90;200m"
    MAGENTA  = "\033[38;2;230;60;180m"
    GRAY     = "\033[38;2;120;130;150m"
    SILVER   = "\033[38;2;180;190;210m"
    WHITE    = "\033[38;2;240;245;250m"
    SPECTRAL = "\033[38;2;200;210;240m"
    SHADOW   = "\033[38;2;60;65;90m"


_COLOR_MAP = {
    "red":     C.RED,
    "crimson": C.CRIMSON,
    "yellow":  C.YELLOW,
    "lime":    C.LIME,
    "gray":    C.GRAY,
    "cyan":    C.CYAN,
    "purple":  C.PURPLE,
    "pink":    C.PINK,
    "green":   C.GREEN,
    "blue":    C.BLUE,
}


def c(text, color_name):
    return f"{_COLOR_MAP.get(color_name, C.WHITE)}{text}{C.RESET}"


_TYPE_COLOR = {
    MODULE_TYPE_AUXILIARY: "blue",
    MODULE_TYPE_GENERIC:   "gray",
    MODULE_TYPE_EXPLOIT:   "red",
}


def _type_label(mod) -> str:
    t = _module_type(mod)
    return c(t, _TYPE_COLOR.get(t, "white"))


# ────────────────────────────────────────────────────────────
#  Output helpers
# ────────────────────────────────────────────────────────────
def ok(msg):       print(f"  {C.GREEN}▸{C.RESET} {msg}")
def err(msg):      print(f"  {C.RED}✗{C.RESET} {msg}")
def info(msg):     print(f"  {C.CYAN}•{C.RESET} {msg}")
def warn(msg):     print(f"  {C.YELLOW}⚠{C.RESET} {msg}")
def spectral(msg): print(f"  {C.PURPLE}◈{C.RESET} {msg}")


_SEP_WIDTH = 58


def hr(color=C.PURPLE, width=_SEP_WIDTH, char="─"):
    print(f"  {color}{char * width}{C.RESET}")


# ────────────────────────────────────────────────────────────
#  Banner & splash
# ────────────────────────────────────────────────────────────
BANNER = [
    r"███████╗██╗██████╗  ██████╗ ██╗      ██████╗ ███╗   ██╗",
    r"██╔════╝██║██╔══██╗██╔═══██╗██║     ██╔═══██╗████╗  ██║",
    r"█████╗  ██║██║  ██║██║   ██║██║     ██║   ██║██╔██╗ ██║",
    r"██╔══╝  ██║██║  ██║██║   ██║██║     ██║   ██║██║╚██╗██║",
    r"███████╗██║██████╔╝╚██████╔╝███████╗╚██████╔╝██║ ╚████║",
    r"╚══════╝╚═╝╚═════╝  ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝",
]


def print_banner(animate=False):
    n = len(BANNER)
    for i, line in enumerate(BANNER):
        t = i / max(n - 1, 1)
        r = int(170 * (1 - t) + 200 * t)
        g = int(80 * (1 - t) + 60 * t)
        b = 255
        sys.stdout.write(f"\033[38;2;{r};{g};{b}m{line}\033[0m\n")
        if animate:
            sys.stdout.flush()
            time.sleep(0.035)
    print(f"\n            {C.GRAY}◈ spectral core · eidolon ◈{C.RESET}  "
          f"{C.PINK}v{VERSION}{C.RESET}\n")


def print_splash():
    steps = [
        (f"{C.PURPLE}◈{C.RESET} initializing {C.CYAN}SPECTRAL CORE{C.RESET}", 0.05),
        (f"{C.PURPLE}◈{C.RESET} calibrating {C.CYAN}EIDOLON PROTOCOLS{C.RESET}", 0.05),
    ]
    for s, d in steps:
        print(f"  {s} ...", end=" ", flush=True)
        time.sleep(d)
        print(f"{C.GREEN}OK{C.RESET}")


# ────────────────────────────────────────────────────────────
#  Table printer
# ────────────────────────────────────────────────────────────
def print_table(headers, rows,
                header_color=C.PINK,
                cell_color=C.WHITE,
                border_color=C.SHADOW,
                title=None):
    if title:
        print(f"\n  {C.PURPLE}▌{C.RESET} {C.BOLD}{title}{C.RESET}")
    widths = [len(str(h)) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(_ANSI_RE.sub("", str(cell))))

    def sep(l, m, r):
        return border_color + l + m.join("─" * (w + 2) for w in widths) + r + C.RESET

    def fmt(cells, color, bold=False):
        out = border_color + "│" + C.RESET
        pre = C.BOLD if bold else ""
        for i, cell in enumerate(cells):
            s = str(cell)
            vis = _ANSI_RE.sub("", s)
            out += (" " + pre + color + s
                    + " " * (widths[i] - len(vis)) + C.RESET + " ")
            out += border_color + "│" + C.RESET
        return out

    print(sep("╭", "┬", "╮"))
    print(fmt(headers, header_color, bold=True))
    print(sep("├", "┼", "┤"))
    for r in rows:
        print(fmt(r, cell_color))
    print(sep("╰", "┴", "╯"))


# ────────────────────────────────────────────────────────────
#  Legacy scaffold cleanup (v3.0.0 → v3.1.0)
# ────────────────────────────────────────────────────────────
def _cleanup_legacy_scaffolds():
    """Remove scaffolds auto-generated by Eidolon v3.0.0, if still pristine.

    Files matching the *original* generated content are removed.  Files that
    the operator has modified are left alone.
    """
    legacy = {
        "_template.py": (
            'NAME        = "My Module"',
            'CATEGORY    = "misc"',
        ),
        "example_sysinfo.py": (
            'NAME        = "System Info"',
            'CATEGORY    = "recon"',
        ),
    }
    for fn, markers in legacy.items():
        path = os.path.join(MODULES_DIR, fn)
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError:
            continue
        if all(m in content for m in markers):
            try:
                os.remove(path)
                spectral(f"removed legacy scaffold: {fn}")
            except OSError as e:
                warn(f"cannot remove legacy {fn}: {e}")


# ────────────────────────────────────────────────────────────
#  Helpers
# ────────────────────────────────────────────────────────────
def _uptime_str() -> str:
    secs = int(time.time() - SESSION_T0)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def _fmt_duration(secs: float) -> str:
    secs = int(secs)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


_INTERNAL_EIDOLON_GLOBALS = frozenset({
    "__eidolon_exit_module__",
    "__eidolon_exit__",
})


# ────────────────────────────────────────────────────────────
#  Main shell
# ────────────────────────────────────────────────────────────
class Eidolon(cmd.Cmd):
    intro        = ""
    use_rawinput = True

    # ── lifecycle ────────────────────────────────────────────
    def __init__(self):
        super().__init__()
        self.globals         = {}
        self.modules         = {}
        self._module_mtimes  = {}
        self.current         = None
        self.current_name    = None
        self.current_options = None

        self.operator_name   = "root"
        self.operator_team   = "eidolon"

        # subshell state
        self._subshell_active      = False
        self._subshell_handler     = None
        self._subshell_completer   = None
        self._subshell_prompt_fn   = None
        self._subshell_on_exit     = None
        self._subshell_session_id  = None

        # session registry (exploits only)
        self.sessions        = {}
        self._next_session_id = 1

        self._update_prompt()

    def preloop(self):
        print_splash()
        self._ensure_modules_dir()
        _cleanup_legacy_scaffolds()
        self.load_modules()
        print()
        spectral(f"welcome back, {C.BOLD}{self.operator_name}{C.RESET}")
        spectral(f"workspace : {C.CYAN}{self.operator_team}{C.RESET} "
                 f"{C.GRAY}·{C.RESET} {C.GREEN}{len(self.modules)}{C.RESET} modules")
        spectral(f"type {C.CYAN}help{C.RESET} for commands.")
        print()

    def postcmd(self, stop, line):
        self._update_prompt()
        return stop

    def emptyline(self):
        return

    def default(self, line):
        token = line.split()[0] if line.strip() else ""
        err(f"unknown command: {C.BOLD}{token}{C.RESET}")
        print(f"     {C.GRAY}try 'help'{C.RESET}")

    # ── prompt ───────────────────────────────────────────────
    def _update_prompt(self):
        if self._subshell_active and callable(self._subshell_prompt_fn):
            try:
                self.prompt = rl_prompt_safe(self._subshell_prompt_fn())
                return
            except Exception:
                pass

        name_part = (f"{C.CYAN}{self.operator_name}"
                     f"{C.GRAY}@{C.CYAN}{self.operator_team}{C.RESET}")

        if self.current_name:
            ctx = f"{C.PINK}{self.current_name}{C.RESET}"
        else:
            ctx = f"{C.GRAY}idle{C.RESET}"

        up = _uptime_str()

        line1 = (f"{C.PURPLE}╭─({name_part}{C.PURPLE})"
                 f"─[{ctx}{C.PURPLE}]"
                 f"─{C.SHADOW}[{up}]{C.PURPLE}")
        line2 = f"{C.PURPLE}╰─{C.PINK}❯{C.RESET} "
        self.prompt = f"\n{rl_prompt_safe(line1)}\n{rl_prompt_safe(line2)}"

    # ── module loading ───────────────────────────────────────
    def _ensure_modules_dir(self):
        try:
            os.makedirs(MODULES_DIR, exist_ok=True)
        except OSError as e:
            warn(f"cannot create modules dir ({MODULES_DIR}): {e}")

    def _iter_module_files(self):
        """Walk MODULES_DIR recursively and yield (path, relpath) tuples.

        Rules:
          - Only *.py files are considered.
          - Files and directories whose names start with '_' or '@'
            are ignored (skipped entirely, not descended into).
        """
        try:
            for root, dirs, files in os.walk(MODULES_DIR):
                dirs[:] = sorted(
                    d for d in dirs if not d.startswith(("_", "@"))
                )
                for fn in sorted(files):
                    if not fn.endswith(".py"):
                        continue
                    if fn.startswith(("_", "@")):
                        continue
                    path = os.path.join(root, fn)
                    rel = os.path.relpath(path, MODULES_DIR).replace(os.sep, "/")
                    yield path, rel
        except OSError as e:
            err(f"cannot walk modules dir: {e}")

    def load_modules(self):
        self.modules = {}
        self._module_mtimes = {}
        try:
            os.makedirs(MODULES_DIR, exist_ok=True)
        except OSError:
            pass
        t0 = time.time()
        failed = 0
        seen_names = set()
        for path, rel in self._iter_module_files():
            name = rel[:-3]
            if name in seen_names:
                warn(f"duplicate module name '{name}' at {path} — skipped")
                failed += 1
                continue
            seen_names.add(name)
            safe_name = name.replace("/", "__")
            try:
                spec = importlib.util.spec_from_file_location(
                    f"eidolon_mod_{safe_name}", path
                )
                if spec is None or spec.loader is None:
                    raise ImportError("cannot build spec")
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                mod.__eidolon_path__ = path
                mod.EIDOLON_GLOBALS  = self.globals
                mod.EIDOLON_SHELL    = self
                if not hasattr(mod, "run"):
                    warn(f"module '{name}' has no run(opts) — skipped")
                    failed += 1
                    continue
                if not hasattr(mod, "NAME"):
                    mod.NAME = name
                self.modules[name] = mod
                try:
                    self._module_mtimes[name] = os.path.getmtime(path)
                except OSError:
                    pass
                if hasattr(mod, "on_load"):
                    try:
                        mod.on_load()
                    except Exception as e:
                        warn(f"{name}.on_load() failed: {e}")
            except Exception as e:
                failed += 1
                err(f"failed to load '{name}': {e}")
        dt = (time.time() - t0) * 1000
        tail = f" · {failed} failed" if failed else ""
        spectral(f"{len(self.modules)} module(s) loaded in {dt:.1f} ms{tail}")

    def _reload_current(self):
        """Reload the selected module from disk ONLY if its file changed.

        Linux philosophy: never silently mutate module state. State-bearing
        modules (a listening REPL, a persistent session) keep running unless
        the operator edits the file.
        """
        if not self.current:
            return
        path = getattr(self.current, "__eidolon_path__", None)
        if not path or not os.path.exists(path):
            return
        name = self.current_name
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return
        if self._module_mtimes.get(name) == mtime:
            return
        try:
            safe_name = name.replace("/", "__")
            spec = importlib.util.spec_from_file_location(
                f"eidolon_mod_{safe_name}", path
            )
            newmod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(newmod)
            newmod.__eidolon_path__ = path
            newmod.EIDOLON_GLOBALS  = self.globals
            newmod.EIDOLON_SHELL    = self
            if hasattr(newmod, "on_load"):
                newmod.on_load()
            new_opts = copy.deepcopy(getattr(newmod, "OPTIONS", {}))
            for k, v in new_opts.items():
                if self.current_options and k in self.current_options:
                    v["value"] = self.current_options[k].get("value", v.get("value"))
            self.current         = newmod
            self.current_options = new_opts
            self.modules[name]   = newmod
            self._module_mtimes[name] = mtime
        except Exception as e:
            warn(f"auto-reload failed (using cached): {e}")

    def _resolve(self, name):
        name = name.strip()
        if name in self.modules:
            return name
        matches = [k for k in self.modules if name in k]
        if len(matches) == 1:
            return matches[0]
        return None

    # ═══════════════════════════════════════════════════════
    #  SESSION SYSTEM (exploits only, read-only listing)
    # ═══════════════════════════════════════════════════════
    def _auto_session_target(self):
        opts = self.current_options or {}
        for key in ("target", "rhost", "rhosts", "host", "hostname", "url", "uri"):
            if key in opts:
                v = opts[key].get("value")
                if v not in (None, "", False):
                    return str(v)
        for k, v in opts.items():
            val = v.get("value")
            if val not in (None, "", False):
                return str(val)
        return ""

    def _open_session(self):
        sid = self._next_session_id
        self._next_session_id += 1
        mod = self.current
        self.sessions[sid] = {
            "id": sid,
            "module": self.current_name or "?",
            "target": self._auto_session_target(),
            "vulnerabilities": _module_vulns(mod) if mod else [],
            "cvss": _module_cvss(mod) if mod else None,
            "started_at": time.time(),
            "closed_at": None,
            "status": "active",
        }
        spectral(f"session {C.PINK}#{sid}{C.RESET} opened · "
                 f"{C.CYAN}{self.current_name}{C.RESET}")
        return sid

    def _close_session(self, sid):
        if sid is None:
            return
        s = self.sessions.get(sid)
        if s and s.get("status") == "active":
            s["closed_at"] = time.time()
            s["status"] = "closed"

    # ═══════════════════════════════════════════════════════
    #  SUBSHELL API
    # ═══════════════════════════════════════════════════════
    def enter_subshell(self, handler, completer=None,
                       prompt_fn=None, on_exit=None):
        self._subshell_active    = True
        self._subshell_handler   = handler
        self._subshell_completer = completer
        self._subshell_prompt_fn = prompt_fn
        self._subshell_on_exit   = on_exit

        # Auto-session for exploit modules
        if (self._subshell_session_id is None
                and self.current is not None
                and _module_type(self.current) == MODULE_TYPE_EXPLOIT):
            self._subshell_session_id = self._open_session()

        self._update_prompt()

    def exit_subshell(self):
        on_exit = self._subshell_on_exit

        if self._subshell_session_id is not None:
            self._close_session(self._subshell_session_id)
            self._subshell_session_id = None

        self._subshell_active    = False
        self._subshell_handler   = None
        self._subshell_completer = None
        self._subshell_prompt_fn = None
        self._subshell_on_exit   = None
        if callable(on_exit):
            try:
                on_exit()
            except Exception as e:
                warn(f"subshell cleanup: {e}")
        self._update_prompt()

    def swap_completer(self, completer):
        import contextlib

        @contextlib.contextmanager
        def _cm():
            try:
                import readline
            except ImportError:
                yield
                return
            saved = readline.get_completer()
            try:
                readline.set_completer(completer)
                readline.parse_and_bind("tab: complete")
                yield
            finally:
                readline.set_completer(saved)
                try:
                    readline.parse_and_bind("tab: complete")
                except Exception:
                    pass
        return _cm()

    def onecmd(self, line):
        if self._subshell_active:
            token = line.strip().split(maxsplit=1)[0] if line.strip() else ""
            if token in ("back", "exit", "quit", "EOF"):
                return super().onecmd(line)
            if callable(self._subshell_handler):
                try:
                    self._subshell_handler(line)
                except Exception as e:
                    err(f"subshell error: {e}")
                return False
            return super().onecmd(line)
        return super().onecmd(line)

    # ═══════════════════════════════════════════════════════
    #  CORE COMMANDS
    # ═══════════════════════════════════════════════════════
    def do_help(self, arg):
        """help [command] — show help"""
        arg = arg.strip()
        if arg:
            meth = getattr(self, f"do_{arg}", None)
            if not meth:
                err(f"no such command: {arg}")
                return
            doc = (meth.__doc__ or "(no help)").strip().splitlines()[0]
            print(f"\n  {C.PINK}{arg}{C.RESET}  —  {doc}\n")
            return

        def sect(title):
            print(f"\n  {C.PURPLE}▌ {title}{C.RESET}")

        print(f"""
{C.PURPLE}╭─────────────────────────────────────────────────────────────╮
│{C.RESET}  {C.PINK}EIDOLON{C.RESET}  {C.GRAY}·{C.RESET}  {C.CYAN}SPECTRAL CORE{C.RESET}  {C.GRAY}·{C.RESET}  quick reference
{C.PURPLE}╰─────────────────────────────────────────────────────────────╯{C.RESET}""")

        sect("CORE")
        print(f"    {C.CYAN}help{C.RESET} [cmd]      this help           "
              f"{C.CYAN}clear{C.RESET}           clear screen")
        print(f"    {C.CYAN}banner{C.RESET}          reprint banner      "
              f"{C.CYAN}reload{C.RESET}          rescan ./modules/")
        print(f"    {C.CYAN}status{C.RESET}          operator status     "
              f"{C.CYAN}whoami{C.RESET}          your profile")
        print(f"    {C.CYAN}operator{C.RESET}        configure identity  "
              f"{C.CYAN}exit{C.RESET} / {C.CYAN}quit{C.RESET}     leave")

        sect("MODULES")
        print(f"    {C.CYAN}modules{C.RESET} / {C.CYAN}list{C.RESET} list       "
              f"{C.CYAN}search{C.RESET} <kw>    search")
        print(f"    {C.CYAN}info{C.RESET} <name>     details      "
              f"{C.CYAN}use{C.RESET} <name>     select")
        print(f"    {C.CYAN}back{C.RESET}            deselect")

        sect("SELECTED MODULE")
        print(f"    {C.CYAN}options{C.RESET}         show options "
              f"{C.CYAN}show options{C.RESET}  alias")
        print(f"    {C.CYAN}set{C.RESET} <k> <v>     set option   "
              f"{C.CYAN}unset{C.RESET} <k>      reset")
        print(f"    {C.CYAN}run{C.RESET} / {C.CYAN}exploit{C.RESET}   execute module")

        sect("SESSIONS")
        print(f"    {C.CYAN}sessions{C.RESET}        list sessions "
              f"{C.CYAN}sessions{C.RESET} <id>  session detail")
        print(f"    {C.GRAY}   exploit subshells auto-register a session{C.RESET}")

        sect("GLOBALS")
        print(f"    {C.CYAN}setg{C.RESET} <k> <v>    global var   "
              f"{C.CYAN}globals{C.RESET}        list globals")
        print(f"    {C.GRAY}   modules read via EIDOLON_GLOBALS dict{C.RESET}\n")

    def do_banner(self, arg):
        """banner — reprint the banner"""
        print_banner(animate=True)

    def do_clear(self, arg):
        """clear — clear screen"""
        os.system("cls" if os.name == "nt" else "clear")

    def do_reload(self, arg):
        """reload — rescan ./modules/ from disk"""
        if self._subshell_active:
            self.exit_subshell()
        spectral("reloading module arsenal ...")
        self.current = self.current_name = self.current_options = None
        self.load_modules()
        ok("arsenal reloaded")

    def do_status(self, arg):
        """status — show operator status card"""
        active = sum(1 for s in self.sessions.values() if s["status"] == "active")
        print()
        print(f"  {C.PURPLE}╭─ OPERATOR STATUS ─────────────────────────────────╮{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}name      {C.RESET}: {C.BOLD}{self.operator_name}{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}team      {C.RESET}: {C.CYAN}{self.operator_team}{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}session   {C.RESET}: {_uptime_str()}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}modules   {C.RESET}: {C.GREEN}{len(self.modules)}{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}globals   {C.RESET}: {C.GREEN}{len(self.globals)}{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}sessions  {C.RESET}: "
              f"{C.GREEN}{active}{C.RESET} active / {len(self.sessions)} total")
        if self.current_name:
            print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}target    {C.RESET}: "
                  f"{C.PINK}{self.current_name}{C.RESET}")
        else:
            print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}target    {C.RESET}: {C.GRAY}idle{C.RESET}")
        print(f"  {C.PURPLE}╰───────────────────────────────────────────────────╯{C.RESET}\n")

    def do_whoami(self, arg):
        """whoami — show your operator profile"""
        self.do_status("")

    def do_operator(self, arg):
        """operator [name <x>|team <x>] — configure operator identity"""
        parts = arg.strip().split(maxsplit=1)
        if not parts:
            print()
            spectral(f"current operator: {C.BOLD}{self.operator_name}{C.RESET} "
                     f"· team {C.CYAN}{self.operator_team}{C.RESET}")
            print(f"     {C.GRAY}usage: operator name <n> | team <n>{C.RESET}\n")
            return

        field = parts[0].lower()
        value = parts[1].strip() if len(parts) > 1 else ""

        if field == "name":
            if not value:
                err("usage: operator name <value>")
                return
            self.operator_name = value
            ok(f"operator name → {C.BOLD}{value}{C.RESET}")

        elif field == "team":
            if not value:
                err("usage: operator team <value>")
                return
            self.operator_team = value
            ok(f"operator team → {C.CYAN}{value}{C.RESET}")

        else:
            err(f"unknown field '{field}'. use name|team")

    def do_exit(self, arg):
        """exit / quit — leave the tool (or current sub-shell)"""
        if self._subshell_active:
            # Documented contract: exit inside a subshell returns to Eidolon.
            self.exit_subshell()
            ok("returned to Eidolon")
            return False
        print(f"\n  {C.PURPLE}╰─{C.RESET} {C.CYAN}eidolon out.{C.RESET}  "
              f"{C.GRAY}session: {_uptime_str()}{C.RESET}\n")
        return True

    do_quit = do_exit

    def do_EOF(self, arg):
        print()
        return self.do_exit(arg)

    # ═══════════════════════════════════════════════════════
    #  MODULE LISTING / SEARCH
    # ═══════════════════════════════════════════════════════
    def do_modules(self, arg):
        """modules / list — list all loaded modules"""
        if not self.modules:
            warn("no modules loaded. add .py files to modules/ and run 'reload'.")
            return
        rows = []
        for i, (name, m) in enumerate(sorted(self.modules.items()), 1):
            cat = getattr(m, "CATEGORY", "-")
            rows.append([
                f"{C.PURPLE}{i:02d}{C.RESET}",
                f"{C.CYAN}{name}{C.RESET}",
                _type_label(m),
                cat,
                str(getattr(m, "AUTHOR", "-")),
                str(getattr(m, "DESCRIPTION", "-"))[:36],
            ])
        print_table(["#", "Arsenal", "Type", "Category", "Author", "Description"],
                    rows, title=f"EIDOLON ARSENAL ({len(self.modules)})")

    do_list = do_modules
    do_ls   = do_modules
    do_arsenal = do_modules

    def do_search(self, arg):
        """search <keyword> — search modules"""
        kw = arg.strip().lower()
        if not kw:
            err("usage: search <keyword>")
            return
        hits = []
        for name, m in self.modules.items():
            blob = " ".join([
                name,
                str(getattr(m, "NAME", "")),
                str(getattr(m, "DESCRIPTION", "")),
                str(getattr(m, "CATEGORY", "")),
                _module_type(m),
                " ".join(_module_vulns(m)),
            ]).lower()
            if kw in blob:
                hits.append(name)
        if not hits:
            warn(f"no modules matched '{kw}'.")
            return
        spectral(f"{len(hits)} match(es):")
        for h in sorted(hits):
            print(f"     {C.PINK}▸{C.RESET} {h}")

    def do_info(self, arg):
        """info <name> — show module details"""
        name = self._resolve(arg)
        if not name:
            err(f"module '{arg.strip()}' not found (or ambiguous)")
            return
        m = self.modules[name]
        mtype = _module_type(m)
        mark = f"  {C.GREEN}● selected{C.RESET}" if name == self.current_name else ""
        print()
        print(f"  {C.PURPLE}╭─ MODULE INTEL ────────────────────────────────────╮{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}name        {C.RESET}: {c(name, C.WHITE)}{mark}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}display     {C.RESET}: {getattr(m,'NAME',name)}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}version     {C.RESET}: {getattr(m,'VERSION','?')}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}author      {C.RESET}: {getattr(m,'AUTHOR','?')}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}category    {C.RESET}: {getattr(m,'CATEGORY','-')}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}type        {C.RESET}: {_type_label(m)}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}description {C.RESET}: {getattr(m,'DESCRIPTION','-')}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}file        {C.RESET}: {getattr(m,'__eidolon_path__','?')}")

        if mtype == MODULE_TYPE_EXPLOIT:
            vulns = _module_vulns(m)
            cvss  = _module_cvss(m)
            sev   = getattr(m, "SEVERITY", None) or _cvss_severity(cvss) or "-"
            vuln_s = ", ".join(vulns) if vulns else "-"
            print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}vulns       {C.RESET}: {vuln_s}")
            if cvss is not None:
                col = _COLOR_MAP.get(_cvss_color(cvss), C.WHITE)
                print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}cvss        {C.RESET}: "
                      f"{col}{cvss:.1f} ({sev}){C.RESET}")
            else:
                print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}cvss        {C.RESET}: -")

        print(f"  {C.PURPLE}╰───────────────────────────────────────────────────╯{C.RESET}")
        opts = getattr(m, "OPTIONS", {})
        if opts:
            rows = [[k, str(v.get("value", "")),
                     "yes" if v.get("required") else "no",
                     v.get("desc", "")] for k, v in opts.items()]
            print_table(["Name", "Default", "Required", "Description"], rows,
                        title="OPTIONS")
        print()

    # ═══════════════════════════════════════════════════════
    #  SELECT / DESELECT
    # ═══════════════════════════════════════════════════════
    def do_use(self, arg):
        """use <name> — select a module"""
        raw = arg.strip()
        if not raw:
            err("usage: use <module>")
            return
        name = self._resolve(raw)
        if not name:
            matches = [k for k in self.modules if raw in k]
            if len(matches) > 1:
                err(f"ambiguous: {', '.join(matches)}")
            else:
                err(f"module '{raw}' not found. try 'modules'.")
            return
        mod = self.modules[name]
        self.current         = mod
        self.current_name    = name
        self.current_options = copy.deepcopy(getattr(mod, "OPTIONS", {}))
        ok(f"selected: {c(name, C.PINK)}  {C.GRAY}·{C.RESET} type {_type_label(mod)}")
        self.do_options("")

    def do_back(self, arg):
        """back — deselect current module (also exits sub-shell)"""
        if self._subshell_active:
            self.exit_subshell()
            ok("exited operator mode")
        if not self.current:
            warn("no module selected.")
            return
        name = self.current_name
        self.current         = None
        self.current_name    = None
        self.current_options = None
        spectral(f"left {name}")

    do_vanish = do_back

    # ═══════════════════════════════════════════════════════
    #  OPTIONS
    # ═══════════════════════════════════════════════════════
    def do_options(self, arg):
        """options — show options of current module"""
        if not self.current:
            err("no module selected. use 'use <module>'.")
            return
        opts = self.current_options or {}
        if not opts:
            info("this module has no options.")
            return
        rows = []
        for k, v in opts.items():
            val = v.get("value", "")
            req = "yes" if v.get("required") else "no"
            rows.append([k, "" if val is None else str(val), req, v.get("desc", "")])
        print_table(["Name", "Value", "Required", "Description"], rows,
                    title=f"OPTIONS · {self.current_name}")

    def do_show(self, arg):
        """show [options|modules] — alias"""
        a = arg.strip().lower()
        if a in ("options", "opt", "o", ""):
            self.do_options("")
        elif a in ("modules", "m"):
            self.do_modules("")
        else:
            err("usage: show [options|modules]")

    @staticmethod
    def _cast(value, reference):
        s = value.strip()
        if isinstance(reference, bool):
            return s.lower() in ("1", "true", "yes", "on", "y")
        if isinstance(reference, int) and not isinstance(reference, bool):
            try:    return int(s)
            except ValueError: return s
        if isinstance(reference, float):
            try:    return float(s)
            except ValueError: return s
        return s

    def do_set(self, arg):
        """set <name> <value> — set an option"""
        if not self.current:
            err("no module selected.")
            return
        try:
            parts = shlex.split(arg)
        except ValueError as e:
            err(f"parse error: {e}")
            return
        if len(parts) < 2:
            err("usage: set <name> <value>")
            return
        key, val = parts[0], " ".join(parts[1:])
        if key not in self.current_options:
            err(f"unknown option: {key}")
            return
        old = self.current_options[key].get("value")
        self.current_options[key]["value"] = self._cast(val, old)
        ok(f"{C.CYAN}{key}{C.RESET} → {self.current_options[key]['value']!r}")

    def do_unset(self, arg):
        """unset <name> — reset option to default"""
        key = arg.strip()
        if not self.current or key not in (self.current_options or {}):
            err(f"unknown option: {key}")
            return
        default = getattr(self.current, "OPTIONS", {}).get(key, {}).get("value", "")
        self.current_options[key]["value"] = copy.deepcopy(default)
        spectral(f"{key} reset to default")

    # ═══════════════════════════════════════════════════════
    #  RUN
    # ═══════════════════════════════════════════════════════
    def do_run(self, arg):
        """run / exploit — execute the selected module"""
        if not self.current:
            err("no module selected.")
            return

        self._reload_current()

        missing = [k for k, v in (self.current_options or {}).items()
                   if v.get("required") and v.get("value") in (None, "", [], {})]
        if missing:
            err(f"missing required option(s): {', '.join(missing)}")
            return

        values = {k: v.get("value") for k, v in self.current_options.items()}
        mtype  = _module_type(self.current)
        ts     = time.strftime("%H:%M:%S")

        hr(C.PURPLE)
        print(f"  {C.PINK}◈{C.RESET} {C.BOLD}EXECUTING OPERATION{C.RESET}")
        print(f"  {C.SHADOW}├─{C.RESET} module   : {C.PINK}{self.current_name}{C.RESET}")
        print(f"  {C.SHADOW}├─{C.RESET} type     : {_type_label(self.current)}")
        print(f"  {C.SHADOW}├─{C.RESET} started  : {C.GRAY}{ts}{C.RESET}")
        print(f"  {C.SHADOW}├─{C.RESET} operator : {C.CYAN}{self.operator_name}{C.RESET}")

        if mtype == MODULE_TYPE_EXPLOIT:
            vulns = _module_vulns(self.current)
            cvss  = _module_cvss(self.current)
            sev   = getattr(self.current, "SEVERITY", None) or _cvss_severity(cvss)
            if vulns:
                print(f"  {C.SHADOW}├─{C.RESET} vulns    : {', '.join(vulns)}")
            if cvss is not None:
                col = _COLOR_MAP.get(_cvss_color(cvss), C.WHITE)
                print(f"  {C.SHADOW}├─{C.RESET} cvss     : {col}{cvss:.1f} ({sev}){C.RESET}")

        if values:
            for i, (k, v) in enumerate(values.items()):
                mark = "├─" if i < len(values) - 1 else "╰─"
                print(f"  {C.SHADOW}{mark}{C.RESET} {k:<10}: {v!r}")
        hr(C.PURPLE)

        start = time.time()
        exit_gut = False
        try:
            self.current.run(values)
        except KeyboardInterrupt:
            warn("interrupted by user.")
        except Exception as e:
            err(f"module error: {e}")
            if os.environ.get("EIDOLON_DEBUG"):
                traceback.print_exc()

        dt = time.time() - start
        if not self._subshell_active:
            hr(C.PURPLE)
            ok(f"operation complete in {dt:.2f}s")

        if self.globals.pop("__eidolon_exit_module__", False):
            self.do_back("")
        if self.globals.pop("__eidolon_exit__", False):
            exit_gut = True

        return exit_gut

    do_exploit = do_run
    do_exec    = do_run
    do_haunt   = do_run

    # ═══════════════════════════════════════════════════════
    #  SESSIONS (read-only)
    # ═══════════════════════════════════════════════════════
    def do_sessions(self, arg):
        """sessions [id] — list sessions or show one session"""
        arg = arg.strip()

        if arg:
            try:
                sid = int(arg.lstrip("#"))
            except ValueError:
                err(f"invalid session id: {arg!r}")
                return
            if sid not in self.sessions:
                err(f"session #{sid} not found")
                return
            self._show_session_detail(sid)
            return

        if not self.sessions:
            info("no sessions recorded.")
            return

        rows = []
        for sid in sorted(self.sessions.keys()):
            s = self.sessions[sid]
            cvss = s.get("cvss")
            if cvss is not None:
                col = _COLOR_MAP.get(_cvss_color(cvss), C.WHITE)
                sev = _cvss_severity(cvss) or ""
                score = f"{col}{cvss:.1f}{C.RESET} {C.GRAY}{sev}{C.RESET}"
            else:
                score = f"{C.GRAY}-{C.RESET}"

            if s["status"] == "active":
                status = f"{C.GREEN}● active{C.RESET}"
            else:
                status = f"{C.GRAY}○ closed{C.RESET}"

            end = s.get("closed_at") or time.time()
            dur = _fmt_duration(end - s.get("started_at", end))

            vulns = ", ".join(s.get("vulnerabilities", [])) or "-"
            rows.append([
                f"{C.PINK}#{sid}{C.RESET}",
                f"{C.CYAN}{s.get('module','-')}{C.RESET}",
                s.get("target", "-") or "-",
                vulns[:24],
                score,
                status,
                dur,
            ])

        print_table(["ID", "Module", "Target", "Vulns", "CVSS", "Status", "Uptime"],
                    rows, title=f"SESSIONS ({len(rows)})")

    def _show_session_detail(self, sid):
        s = self.sessions[sid]
        cvss = s.get("cvss")
        sev  = _cvss_severity(cvss)
        started = time.strftime("%H:%M:%S", time.localtime(s.get("started_at", 0)))
        if s.get("closed_at"):
            closed = time.strftime("%H:%M:%S", time.localtime(s["closed_at"]))
            dur = s["closed_at"] - s.get("started_at", s["closed_at"])
        else:
            closed = "-"
            dur = time.time() - s.get("started_at", time.time())

        vulns = s.get("vulnerabilities", [])
        status = (f"{C.GREEN}active{C.RESET}" if s["status"] == "active"
                  else f"{C.GRAY}closed{C.RESET}")

        print()
        print(f"  {C.PURPLE}╭─ SESSION #{sid} ────────────────────────────────────╮{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}module    {C.RESET}: {C.CYAN}{s.get('module','?')}{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}target    {C.RESET}: {s.get('target') or '-'}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}vulns     {C.RESET}: "
              f"{', '.join(vulns) if vulns else '-'}")
        if cvss is not None:
            col = _COLOR_MAP.get(_cvss_color(cvss), C.WHITE)
            print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}cvss      {C.RESET}: "
                  f"{col}{cvss:.1f} ({sev}){C.RESET}")
        else:
            print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}cvss      {C.RESET}: -")
        print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}status    {C.RESET}: {status}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}started   {C.RESET}: {started}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}closed    {C.RESET}: {closed}")
        print(f"  {C.PURPLE}│{C.RESET}  {C.PINK}duration  {C.RESET}: {_fmt_duration(dur)}")
        print(f"  {C.PURPLE}╰───────────────────────────────────────────────────╯{C.RESET}")
        print()

    # ═══════════════════════════════════════════════════════
    #  GLOBALS
    # ═══════════════════════════════════════════════════════
    def do_setg(self, arg):
        """setg <name> <value> — set a global variable"""
        try:
            parts = shlex.split(arg)
        except ValueError as e:
            err(f"parse error: {e}")
            return
        if len(parts) < 2:
            err("usage: setg <name> <value>")
            return
        key, val = parts[0], " ".join(parts[1:])
        self.globals[key] = val
        ok(f"global {C.CYAN}{key}{C.RESET} → {val!r}")

    def do_globals(self, arg):
        """globals — list global variables"""
        items = [(k, v) for k, v in self.globals.items()
                 if k not in _INTERNAL_EIDOLON_GLOBALS]
        if not items:
            info("no globals set. use 'setg <name> <value>'.")
            return
        rows = [[k, v] for k, v in items]
        print_table(["Name", "Value"], rows, title="GLOBAL VARIABLES")

    # ═══════════════════════════════════════════════════════
    #  TAB COMPLETION
    # ═══════════════════════════════════════════════════════
    def complete_use(self, text, *_):
        return [m for m in self.modules if m.startswith(text)]

    def complete_info(self, text, *_):
        return [m for m in self.modules if m.startswith(text)]

    def complete_set(self, text, *_):
        return [k for k in (self.current_options or {}) if k.startswith(text)]

    def complete_unset(self, text, *_):
        return self.complete_set(text)

    def complete_operator(self, text, *_):
        return [x for x in ["name", "team"] if x.startswith(text)]

    def complete_help(self, text, *_):
        cmds = ["help", "banner", "clear", "reload", "exit", "quit", "modules",
                "list", "ls", "arsenal", "search", "info", "use", "back", "vanish",
                "options", "set", "unset", "run", "exploit", "exec", "haunt", "show",
                "setg", "globals", "status", "whoami", "operator", "sessions"]
        return [x for x in cmds if x.startswith(text)]

    def completedefault(self, text, line, begidx, endidx):
        if self._subshell_active and callable(self._subshell_completer):
            try:
                return self._subshell_completer(text, line, begidx, endidx)
            except Exception:
                return []
        return []


# ────────────────────────────────────────────────────────────
def main():
    if "--no-banner" not in sys.argv:
        print_banner(animate=True)
    else:
        print(f"  {C.PINK}Eidolon{C.RESET}  "
              f"{C.GRAY}· {CODENAME} ·{C.RESET}  "
              f"{C.PINK}v{VERSION}{C.RESET}\n")

    shell = Eidolon()
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print()
        shell.do_exit("")
    except EOFError:
        shell.do_exit("")


if __name__ == "__main__":
    main()
