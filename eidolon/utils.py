import sys
import time
from eidolon.colors import C, _ANSI_RE

def ok(msg):       print(f"  {C.GREEN}▸{C.RESET} {msg}")
def err(msg):      print(f"  {C.RED}✗{C.RESET} {msg}")
def info(msg):     print(f"  {C.CYAN}•{C.RESET} {msg}")
def warn(msg):     print(f"  {C.YELLOW}⚠{C.RESET} {msg}")
def spectral(msg): print(f"  {C.PURPLE}◈{C.RESET} {msg}")

_SEP_WIDTH = 58
def hr(color=C.PURPLE, width=_SEP_WIDTH, char="─"):
    print(f"  {color}{char * width}{C.RESET}")

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
    print(f"\n            {C.GRAY}◈ spectral core · eidolon ◈{C.RESET}  {C.PINK}v3.1.0{C.RESET}\n")

def print_splash():
    steps = [
        (f"{C.PURPLE}◈{C.RESET} initializing {C.CYAN}SPECTRAL CORE{C.RESET}", 0.05),
        (f"{C.PURPLE}◈{C.RESET} calibrating {C.CYAN}EIDOLON PROTOCOLS{C.RESET}", 0.05),
    ]
    for s, d in steps:
        print(f"  {s} ...", end=" ", flush=True)
        time.sleep(d)
        print(f"{C.GREEN}OK{C.RESET}")

def print_table(headers, rows, header_color=C.PINK, cell_color=C.WHITE, border_color=C.SHADOW, title=None):
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
            out += (" " + pre + color + s + " " * (widths[i] - len(vis)) + C.RESET + " ")
            out += border_color + "│" + C.RESET
        return out

    print(sep("╭", "┬", "╮"))
    print(fmt(headers, header_color, bold=True))
    print(sep("├", "┼", "┤"))
    for r in rows:
        print(fmt(r, cell_color))
    print(sep("╰", "┴", "╯"))

def _uptime_str(start_time):
    secs = int(time.time() - start_time)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"

def _fmt_duration(secs: float) -> str:
    secs = int(secs)
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"

def _cvss_severity(score):
    if score is None: return None
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score > 0.0: return "low"
    return "none"

def _cvss_color(score):
    if score is None: return None
    if score >= 9.0: return "red"
    if score >= 7.0: return "crimson"
    if score >= 4.0: return "yellow"
    if score > 0.0: return "lime"
    return "gray"

def _module_vulns(mod) -> list:
    v = getattr(mod, "VULNERABILITIES", None) or getattr(mod, "VULNERABILITY", None) or getattr(mod, "CVE", None)
    if v is None: return []
    if isinstance(v, str): return [v]
    try: return [str(x) for x in v]
    except TypeError: return [str(v)]

def _module_cvss(mod):
    v = getattr(mod, "CVSS", None)
    if v is None: return None
    try: return float(v)
    except (TypeError, ValueError): return None
