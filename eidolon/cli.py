import os
import sys
import cmd
import copy
import threading
import time
import shlex
import traceback
import shutil
import glob
import getpass
import importlib.util

try:
    import readline
    readline.set_completer_delims(' \t\n')
    readline.parse_and_bind("tab: complete")
except ImportError:
    pass

from pathlib import Path

from eidolon.colors import C, rl_prompt_safe, c
from eidolon.utils import (
    ok, err, info, warn, spectral, hr, print_banner, print_splash, print_table,
    _uptime_str, _fmt_duration, _cvss_severity, _cvss_color,
    _module_vulns, _module_cvss, version_tuple, sha256_of_path,
)
from eidolon.loader import (
    iter_module_files, load_module_from_path, _module_type, _cleanup_legacy_scaffolds,
    TrustManager,
    MODULE_TYPE_EXPLOIT, MODULE_TYPE_AUXILIARY, MODULE_TYPE_GENERIC,
    MODULE_TYPE_PAYLOAD, MODULE_TYPE_LISTENER,
)
from eidolon.jobs import JobManager
from eidolon.database import EidolonDB
from eidolon.repo import RepositoryManager, encrypt_package
from eidolon import __version__, CODENAME

WORKSPACE_DIR = os.path.join(os.path.expanduser("~"), ".eidolon")
MODULES_DIR = os.path.join(WORKSPACE_DIR, "modules")
DB_PATH = os.path.join(WORKSPACE_DIR, "eidolon.db")

_version_tuple = version_tuple  # backwards-compat

_TYPE_COLOR = {
    MODULE_TYPE_AUXILIARY: "blue",
    MODULE_TYPE_GENERIC:   "gray",
    MODULE_TYPE_EXPLOIT:   "red",
    MODULE_TYPE_PAYLOAD:   "purple",
}

_TRUST_COLOR = {
    "ok":        C.GREEN,
    "untrusted": C.YELLOW,
    "modified":  C.RED,
    "missing":   C.GRAY,
    "unreadable": C.RED,
}

_NEW_MODULE_TEMPLATE = '''"""
__NAME__ — Eidolon module (scaffolded by `new_module`)

╔══════════════════════════════════════════════════════════════════════════╗
║  DEVELOPER FIELD GUIDE — read once, then delete whatever you do not need  ║
╚══════════════════════════════════════════════════════════════════════════╝

THE CONTRACT — the framework requires exactly two names:
  * OPTIONS  : {KEY: {"value": default, "required": bool, "desc": str}}
               the `set KEY value` command fills these; required keys are
               validated automatically BEFORE run() ever fires.
  * run(opts): receives {KEY: value}. Everything else below is optional.

MODULE TYPES (MODULE_TYPE — one of):
  auxiliary : investigation/support — scans, OSINT, fuzzing, sniffing, brute
              force, DoS tests, parsers. Attacks nothing directly.
  exploit   : the weapon delivery — gains initial code execution, takes a
              payload (optional!). Gets automatic session logging in the DB.
  payload   : the payload BUILDER — the framework ships no payload sources
              and no compilers: THIS module owns them. Its sources sit beside
              the script; the script builds the artifact in any language
              (go, nim, c, rust, c#, bash, python, powershell, …) with the
              listener profile embedded and registers it in the typed store
              (see PAYLOAD INTEGRATION below).
  listener  : the C2 side — starts a long-running server with whatever
              transport and libraries it likes (ws, tcp, http, grpc, …),
              registers sessions into wraith.sessions.default_registry(),
              publishes its profile via EIDOLON_SHELL.wraith_listener
              (.url/.token/.tags) and defines stop(). `gen <module>` or
              `run --bg` turns it into a managed background job.
  generic   : everything else (encode/convert/package/report — non-attack helpers).

FREE INTERNAL LAYOUT — the framework knows exactly ONE file, this entry
  script. Everything around it is yours: sibling .py files, _src/ with raw
  sources in any language, assets, data — import siblings relative to
  __eidolon_path__. No naming convention, no required subfolders.

METADATA the CLI displays in `info` / `modules` / remote indexes:
  NAME, VERSION, DESCRIPTION, CATEGORY, MODULE_TYPE, AUTHOR, PAYLOAD_KIND

PAYLOAD FREEDOM (the deepest rule of Eidolon):
  An exploit is only a DELIVERY MECHANISM. What is delivered is yours and the
  operator's decision — raw file, shellcode, shell one-liner, generated source,
  multi-stage downloader, anything. The framework enforces nothing. The four
  classic shapes below are ADVISORY PATTERNS, not a contract:
    SHELLCODE_PATH  raw position-independent code — YOUR bug defines arch,
                    badchars, max size: validate those in run().
    PAYLOAD_FILE    compiled artifact dropped/uploaded on the target.
    CMD             shell command (bash/zsh/cmd/...), e.g. piping an implant
                    from a URL. You own the quoting and escaping.
    PAYLOAD_SRC     source an interpreter on the target executes.

PAYLOAD INTEGRATION with a LISTENER module (wraith kernel) — the dedicated field:
  EXPLOIT side — declare one option and the framework does the bookkeeping:

      OPTIONS = {
          "payload": {"value": "", "required": False,
                      "desc":  "payload name from `c2 payloads`, or a raw path",
                      "kind":  "payload",                    # framework-managed
                      "types": ("file-posix",)},             # accepted types
      }

  `set payload ghost-go` resolves LIVE against the typed store — a payload
  whose type is outside `types` is refused on the spot. At run() the value is
  already a manifest DICT (raw ref string never reaches you):

      def run(opts):
          payload = opts.get("payload")            # None when unset
          if payload:
              artifact = payload["path"]           # ready to deliver
              # payload["type"], ["protocol"], ["sha256"], ["name"] …
  A raw file path always passes as type "external" — freedom stays total.

  PAYLOAD-BUILDER side (type "payload") — build ANY language and register:

      lsn = EIDOLON_SHELL.wraith_listener          # url / token / tags
      # compile/produce your artifact with lsn.url + lsn.token embedded, then:
      from wraith import store
      store.register_payload("ghost-go", artifact, ptype="file-posix",
                             backend="go", target_os="linux", arch="x86_64",
                             note="compiled by ghost-implant module",
                             protocol_tag="ws-json-async")
  `c2 payloads` lists it; exploits pick it by name — type-filtered.

INJECTED BY THE FRAMEWORK (available inside run, zero setup):
  opts              {KEY: value} — resolved option values (strings)
  EIDOLON_GLOBALS   shared global dict — see setg/globals; persist small state
  EIDOLON_SHELL     the live console instance (internal API — use sparingly)
  __eidolon_path__  absolute path of this file (resolve sibling assets from it)

DEPENDENCIES: list pip names in REQUIREMENTS — they are DISPLAYED (`deps`),
  NEVER installed by the framework (supply-chain safety). The operator runs:

      pip install <name>

LIFECYCLE HOOK:
  on_load()      runs once when the module is loaded — early sanity checks,
                  toolchain discovery, reading env; anything cheap and safe.
  stop()         listener / long-running modules: cleanly halt the engine
                 (close sockets, stop loops). This is what `kill <id>` calls;
                 a listener without stop() cannot be killed.

HOUSE STYLE (helps reviewers read you):
  * talk to the operator only through eidolon.utils: ok / err / info / warn /
    spectral — the console owns all coloring.
  * network I/O: ALWAYS an explicit timeout, ALWAYS str(err) through err().
  * filesystem: whitelists, os.path.realpath containment, no eval/exec ever.
  * payloads are written to disk with 0o600 when they contain real keys.
"""

from eidolon.utils import ok, err, info, warn, spectral

NAME        = "__NAME__"
VERSION     = "0.1.0"
DESCRIPTION = "TODO: one sharp line — what breaking through this does"
CATEGORY    = "__CATEGORY__"
MODULE_TYPE = "__TYPE__"          # auxiliary | generic | exploit | payload | listener
AUTHOR      = "__AUTHOR__"

# display-only (the framework never enforces it) — classic shapes:
# shellcode | file | cmd | code | none
PAYLOAD_KIND = "none"

# pip names only — DISPLAYED by `deps`, never auto-installed (security rule).
REQUIREMENTS = []


OPTIONS = {
    # required options are validated automatically before run() fires
    "target": {
        "value":    "",
        "required": True,
        "desc":     "who this runs against (host, URL, or path)",
    },
    # optional knobs — delete what you do not need
    "verbose": {
        "value":    False,
        "required": False,
        "desc":     "print every step",
    },
    # dedicated payload field for exploit/payload modules — uncomment if relevant:
    # "payload": {
    #     "value":    "",
    #     "required": False,
    #     "desc":     "payload name from `c2 payloads`, or a raw file path",
    #     "kind":     "payload",                 # framework-managed: validated
    #     "types":    ("file-posix",),           # on set, manifest dict at run
    # },
}


def on_load():
    """Optional lifecycle hook — runs once at module load. Cheap+safe only;
    loading must never have side effects on the target."""
    # spectral("__NAME__ ready")
    return None


def _fail(msg):
    """Uniform failure exit for modules that abort on errors mid-flight."""
    err(msg)
    raise SystemExit(1)


def run(opts):
    """THE entry point. opts = {KEY: value}; required keys already validated."""
    target  = opts.get("target", "")
    verbose = str(opts.get("verbose", "")).lower() in ("1", "true", "yes")

    info(f"__NAME__: engaging {target!r}")

    # ── 1. validate what the bug requires — the framework cannot know this ──
    if not target:
        return err("target is empty — set it with: set target <value>")

    # ── 2. (exploit/payload modules) the dedicated payload field ───────────
    # `kind: "payload"` options arrive as a manifest DICT with "path" inside;
    # raw file paths pass as type "external". Nothing to resolve by hand here.
    # payload = opts.get("payload")
    # if payload and verbose:
    #     info(f"payload: {payload['name']} [{payload['type']}]")

    # ── 3. the actual work — network calls carry timeouts, errors are non-fatal ──
    try:
        # import requests
        # resp = requests.get(f"https://{target}", timeout=10, verify=True)
        # if verbose: print("status:", resp.status_code)
        pass
    except Exception as e:
        return err(f"failed: {e}")

    # ── 4. report ────────────────────────────────────────────────────────────
    ok("__NAME__ finished — nothing was harmed in this scaffold")
'''


def _type_label(mod) -> str:
    t = _module_type(mod)
    return c(t, _TYPE_COLOR.get(t, "white"))


def _missing_requirements(reqs) -> list:
    missing = []
    for r in reqs:
        try:
            if importlib.util.find_spec(str(r)) is None:
                missing.append(str(r))
        except (ImportError, ValueError):
            missing.append(str(r))
    return missing


class Eidolon(cmd.Cmd):
    intro = ""
    use_rawinput = True

    def __init__(self):
        super().__init__()
        os.makedirs(MODULES_DIR, exist_ok=True)
        self.db = EidolonDB(DB_PATH)
        self.repo_mgr = RepositoryManager()
        self.trust_mgr = TrustManager(modules_dir=MODULES_DIR)
        self.globals = self.db.get_globals()
        self.modules = {}
        self._module_mtimes = {}
        self._untrusted = {}   # {module_key: status} — untrusted/modified/missing files
        self.current = None
        self.current_name = None
        self.current_options = None
        self._wraith_listener = None
        self._wraith_lock = threading.RLock()
        self.jobs = JobManager()

        self.session_t0 = time.time()
        self.operator_name = "root"
        self.operator_team = "eidolon"
        self._subshell_active = False
        self._subshell_handler = None
        self._subshell_completer = None
        self._subshell_prompt_fn = None
        self._subshell_on_exit = None
        self._subshell_session_id = None
        self._update_prompt()

    def preloop(self):
        print_splash()
        _cleanup_legacy_scaffolds(MODULES_DIR)
        # Clean up trust entries whose files were deleted
        try:
            purged = self.trust_mgr.purge_orphans()
            if purged:
                spectral(f"purged {len(purged)} orphan trust entr{'y' if len(purged)==1 else 'ies'}")
        except Exception as e:
            warn(f"trust purge failed: {e}")

        self.load_modules()
        print()
        spectral(f"welcome back, {C.BOLD}{self.operator_name}{C.RESET}")
        spectral(f"workspace : {C.CYAN}{WORKSPACE_DIR}{C.RESET}")
        spectral(f"modules   : {C.GREEN}{len(self.modules)}{C.RESET} loaded"
                 + (f" · {C.YELLOW}{len(self._untrusted)} untrusted{C.RESET}" if self._untrusted else ""))
        if self._untrusted:
            warn(f"{len(self._untrusted)} module(s) blocked by TOFU. run 'trusted' to inspect.")
        spectral(f"type {C.CYAN}help{C.RESET} for commands.\n")

    def postcmd(self, stop, line):
        self._update_prompt()
        return stop

    def emptyline(self): return

    def default(self, line):
        token = line.split()[0] if line.strip() else ""
        err(f"unknown command: {C.BOLD}{token}{C.RESET}")

    def _update_prompt(self):
        if self._subshell_active and callable(self._subshell_prompt_fn):
            try:
                self.prompt = rl_prompt_safe(self._subshell_prompt_fn())
                return
            except Exception: pass

        name_part = f"{C.CYAN}{self.operator_name}{C.GRAY}@{C.CYAN}{self.operator_team}{C.RESET}"
        ctx = f"{C.PINK}{self.current_name}{C.RESET}" if self.current_name else f"{C.GRAY}idle{C.RESET}"
        up = _uptime_str(self.session_t0)

        line1 = f"{C.PURPLE}╭─({name_part}{C.PURPLE})─[{ctx}{C.PURPLE}]─{C.SHADOW}[{up}]{C.PURPLE}"
        line2 = f"{C.PURPLE}╰─{C.PINK}❯{C.RESET} "
        self.prompt = f"\n{rl_prompt_safe(line1)}\n{rl_prompt_safe(line2)}"

    # ═════════════════════════════════════════════════════════
    # MODULE LOADING WITH TOFU GATE
    # ═════════════════════════════════════════════════════════
    def load_modules(self):
        self.modules = {}
        self._module_mtimes = {}
        self._untrusted = {}
        t0 = time.time()
        failed = 0
        untrusted = 0
        seen_names = set()

        for path, rel in iter_module_files(MODULES_DIR):
            name = rel[:-3]
            if name in seen_names:
                warn(f"duplicate module '{name}' — skipped")
                failed += 1
                continue
            seen_names.add(name)

            # ── TOFU gate ──
            trusted, status = self.trust_mgr.is_trusted(name, path)
            if not trusted:
                self._untrusted[name] = status
                untrusted += 1
                continue

            mod, error = load_module_from_path(path, self.globals, self)
            if error:
                failed += 1
                err(f"failed to load '{name}': {error}")
                continue

            if not hasattr(mod, "run"):
                warn(f"module '{name}' has no run(opts) — skipped")
                failed += 1
                continue
            if not hasattr(mod, "NAME"): mod.NAME = name

            self.modules[name] = mod
            try: self._module_mtimes[name] = os.path.getmtime(path)
            except OSError: pass

            if hasattr(mod, "on_load"):
                try: mod.on_load()
                except Exception as e: warn(f"{name}.on_load() failed: {e}")

        dt = (time.time() - t0) * 1000
        tail = f" · {failed} failed" if failed else ""
        if untrusted:
            tail += f" · {C.YELLOW}{untrusted} untrusted{C.RESET}"
        spectral(f"{len(self.modules)} module(s) loaded in {dt:.1f} ms{tail}")

    def _resolve(self, name):
        name = name.strip()
        known = list(self.modules.keys()) + list(self._untrusted.keys())
        if name in known: return name
        matches = [k for k in known if name in k]
        return matches[0] if len(matches) == 1 else None

    def _is_module_installed(self, target_name):
        target_clean = target_name.replace("-", "_")
        known = list(self.modules.keys()) + list(self._untrusted.keys())
        for existing_name in known:
            existing_base = os.path.basename(existing_name).replace("-", "_")
            if existing_base == target_clean:
                return existing_name
        return None

    def _auto_session_target(self):
        opts = self.current_options or {}
        for key in ("target", "rhost", "rhosts", "host", "hostname", "url", "uri"):
            if key in opts:
                v = opts[key].get("value")
                if v not in (None, "", False): return str(v)
        return ""

    def enter_subshell(self, handler, completer=None, prompt_fn=None, on_exit=None):
        self._subshell_active = True
        self._subshell_handler = handler
        self._subshell_completer = completer
        self._subshell_prompt_fn = prompt_fn
        self._subshell_on_exit = on_exit
        if (self._subshell_session_id is None and self.current is not None
                and _module_type(self.current) == MODULE_TYPE_EXPLOIT):
            sid = self.db.add_session(
                self.current_name, self._auto_session_target(),
                _module_vulns(self.current), _module_cvss(self.current)
            )
            self._subshell_session_id = sid
            spectral(f"session {C.PINK}#{sid}{C.RESET} opened")
        self._update_prompt()

    def exit_subshell(self):
        on_exit = self._subshell_on_exit
        if self._subshell_session_id is not None:
            self.db.close_session(self._subshell_session_id)
            self._subshell_session_id = None
        self._subshell_active = False
        if callable(on_exit):
            try: on_exit()
            except Exception as e: warn(f"subshell cleanup: {e}")
        self._update_prompt()

    def onecmd(self, line):
        if self._subshell_active:
            token = line.strip().split(maxsplit=1)[0] if line.strip() else ""
            if token in ("back", "exit", "quit", "EOF"): return super().onecmd(line)
            if callable(self._subshell_handler):
                try: self._subshell_handler(line)
                except Exception as e: err(f"subshell error: {e}")
                return False
        return super().onecmd(line)

    # ═════════════════════════════════════════════════════════
    # REPO COMMANDS
    # ═════════════════════════════════════════════════════════
    def do_repo(self, arg):
        """repo [list|add|remove|enable|disable|priority|sync|search|list-modules|stats|check|install|upgrade|update-all|pack|source|info]"""
        args = arg.strip().split()
        if not args:
            return self.do_repo("list")

        cmd = args[0].lower()

        if cmd in ("list", "remotes"):
            remotes = self.repo_mgr.remotes
            if not remotes:
                return warn("No remotes configured.")
            rows = []
            for r in remotes:
                status = (f"{C.GREEN}Enabled{C.RESET}" if r.get("enabled", True)
                          else f"{C.RED}Disabled{C.RESET}")
                rows.append([str(r.get("priority", 10)), status, r["url"]])
            print_table(["Priority", "Status", "Remote URL"], rows, title="CONFIGURED REMOTES")
            return

        if cmd == "add":
            validate = not any(a in ("--no-validate", "-n") for a in args)
            urls = [a for a in args[1:] if not a.startswith("-")]
            if not urls:
                return err("usage: repo add <url> [--no-validate]")
            url = urls[0]
            success, reason = self.repo_mgr.add_remote(url, validate=validate)
            if success:
                ok(f"Added remote: {C.CYAN}{url}{C.RESET}")
                warn("Remote modules will be UNTRUSTED after install — verify before trusting.")
            elif "already exists" in reason:
                warn(reason)
            else:
                err(f"Failed to add: {reason}")
            return

        if cmd == "remove" and len(args) > 1:
            if self.repo_mgr.remove_remote(args[1]):
                ok(f"Removed remote: {args[1]}")
            else:
                warn("Remote not found.")
            return

        if cmd == "enable" and len(args) > 1:
            ok("Remote enabled.") if self.repo_mgr.toggle_remote(args[1], True) else err("Remote not found.")
            return

        if cmd == "disable" and len(args) > 1:
            ok("Remote disabled.") if self.repo_mgr.toggle_remote(args[1], False) else err("Remote not found.")
            return

        if cmd == "priority" and len(args) > 2:
            try:
                prio = int(args[2])
            except ValueError:
                return err("Priority must be an integer.")
            ok(f"Remote priority set to {prio}.") if self.repo_mgr.set_priority(args[1], prio) else err("Remote not found.")
            return

        if cmd == "sync":
            spectral("Syncing metadata from enabled remotes…")
            count = self.repo_mgr.sync_json(force_refresh=True)
            ok(f"Cached metadata from {count} remote(s).")
            return

        if cmd in ("list-modules", "avail", "search"):
            modules = self.repo_mgr.get_all_modules()
            if not modules:
                return warn("No modules found in any remote.")
            if cmd == "search":
                if len(args) < 2:
                    return err("usage: repo search <keyword>")
                kw = args[1].lower()
                filtered = {
                    k: v for k, v in modules.items()
                    if kw in f"{k} {v.get('description', '')} {v.get('tags', '')} {v.get('cve', '')} {v.get('protocol', '')} {v.get('payload_type', '')}".lower()
                }
            else:
                filtered = modules
            if not filtered:
                return warn("No matching modules.")
            rows = []
            for name, minfo in sorted(filtered.items()):
                tags = minfo.get("tags", [])
                meta = ", ".join(tags) if isinstance(tags, list) else str(tags or "")
                proto = minfo.get("protocol")
                if proto:
                    meta = f"{meta} | {C.CYAN}{proto}{C.RESET}" if meta else f"{C.CYAN}{proto}{C.RESET}"
                cve = minfo.get("cve")
                if cve:
                    meta = f"{meta} | {C.RED}{cve}{C.RESET}" if meta else f"{C.RED}{cve}{C.RESET}"
                rows.append([
                    f"{C.CYAN}{name}{C.RESET}",
                    minfo.get("version", "-"),
                    minfo.get("type", "tar"),
                    (meta or "-")[:35],
                ])
            print_table(["Module Name", "Version", "Type", "Tags / CVE"], rows,
                        title=f"AVAILABLE MODULES ({len(filtered)})")
            return

        if cmd == "info":
            if len(args) < 2:
                return err("usage: repo info <name>")
            modules = self.repo_mgr.get_all_modules()
            if args[1] not in modules:
                return err(f"Module '{args[1]}' not found in remotes.")
            m = modules[args[1]]
            tags = m.get("tags", [])
            tags_str = ", ".join(tags) if isinstance(tags, list) else str(tags or "")
            print(f"\n  {C.PURPLE}╭─ REMOTE MODULE INTEL ──────────────╮{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET} name : {C.CYAN}{args[1]}{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET} path : {m.get('path', args[1])}")
            print(f"  {C.PURPLE}│{C.RESET} type : {m.get('type', 'tar')} | ver: {m.get('version', '-')}")
            if m.get("payload_type"):
                print(f"  {C.PURPLE}│{C.RESET} payload type : {C.PINK}{m['payload_type']}{C.RESET}")
            if m.get("protocol"):
                print(f"  {C.PURPLE}│{C.RESET} protocol     : {C.CYAN}{m['protocol']}{C.RESET} {C.GRAY}(wire dialect pinned by the index){C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET} desc : {m.get('description', '-')}")
            if tags_str:
                print(f"  {C.PURPLE}│{C.RESET} tags : {C.LIME}{tags_str}{C.RESET}")
            if m.get("cve"):
                cvss = m.get("cvss")
                cvss_str = f" (CVSS: {cvss})" if cvss is not None else ""
                print(f"  {C.PURPLE}│{C.RESET} vuln : {C.RED}{m['cve']}{cvss_str}{C.RESET}")
            if m.get("sha256"):
                print(f"  {C.PURPLE}│{C.RESET} sha  : {C.GRAY}{m['sha256'][:24]}…{C.RESET}")
            if m.get("enc") or m.get("encrypted"):
                enc_note = "password in index" if (m.get("password") or m.get("key")) else "password prompted at install"
                print(f"  {C.PURPLE}│{C.RESET} enc  : {C.YELLOW}encrypted package{C.RESET} ({enc_note})")
            print(f"  {C.PURPLE}│{C.RESET} url  : {m.get('url', '-')}")
            print(f"  {C.PURPLE}╰────────────────────────────────────╯\n")
            return

        if cmd == "stats":
            s = self.repo_mgr.stats()
            trust_entries = self.trust_mgr.list_all()
            trusted_ct = sum(1 for e in trust_entries.values() if e.get("trusted"))
            print(f"\n  {C.PURPLE}╭─ REPOSITORY STATISTICS ────────────╮{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  Remotes     : {s['remotes']} ({s['enabled']} enabled)")
            print(f"  {C.PURPLE}│{C.RESET}  Modules     : {s['modules']} available")
            print(f"  {C.PURPLE}│{C.RESET}  Cache Size  : {s['cache_bytes'] / 1024:.2f} KB")
            print(f"  {C.PURPLE}│{C.RESET}  Trust       : {C.GREEN}{trusted_ct}{C.RESET} trusted / {len(trust_entries)} registered")
            print(f"  {C.PURPLE}╰────────────────────────────────────╯\n")
            return

        if cmd == "check":
            all_remote = self.repo_mgr.get_all_modules()
            rows = []
            for local_name in self.modules:
                remote_key, remote_info = self.repo_mgr.find_by_local_name(local_name, all_remote)
                if not remote_key:
                    continue
                rows.append([
                    remote_key,
                    getattr(self.modules[local_name], "VERSION", "-"),
                    remote_info.get("version", "-"),
                ])
            if not rows:
                return info("no installed modules have a remote source")
            print_table(["Module", "Local VERSION", "Index version"], rows,
                        title="REMOTE-SOURCED MODULES (index version is informational — updates are manual)")
            return

        if cmd == "install":
            force = any(a in ("--force", "-f") for a in args)
            names = [a for a in args[1:] if not a.startswith("-")]
            if not names:
                return err("usage: repo install <name> [--force]")
            mod_name = names[0]

            if not force:
                existing = self._is_module_installed(mod_name)
                if existing:
                    return warn(
                        f"Module '{mod_name}' already installed at '{existing}'. "
                        f"Use 'repo install {mod_name} --force' or 'remove {existing}' first."
                    )

            modules = self.repo_mgr.get_all_modules()
            if mod_name not in modules:
                return err(f"Module '{mod_name}' not found in any remote.")

            success, reason = self.repo_mgr.install_module(
                modules[mod_name], force=force, trust_mgr=self.trust_mgr
            )
            if success:
                ok(f"Module '{mod_name}' installed.")
                warn(f"UNTRUSTED — run {C.PINK}trusted{C.RESET} to inspect, then {C.PINK}trust <path>{C.RESET} to enable.")
                self.load_modules()
            else:
                err(f"Installation failed: {reason}")
            return

        if cmd in ("upgrade", "update-all"):
            all_remote = self.repo_mgr.get_all_modules()
            to_update = []

            if cmd == "upgrade" and len(args) > 1:
                local_name = self._resolve(args[1])
                if not local_name:
                    return err(f"Module '{args[1]}' not installed.")
                remote_key, remote_info = self.repo_mgr.find_by_local_name(local_name, all_remote)
                if not remote_key:
                    return err(f"Module '{args[1]}' has no remote source.")
                to_update.append((local_name, remote_key, remote_info))
            else:
                for local_name in self.modules:
                    remote_key, remote_info = self.repo_mgr.find_by_local_name(local_name, all_remote)
                    if remote_key:
                        to_update.append((local_name, remote_key, remote_info))
                if not to_update:
                    return ok("nothing to update — no installed module has a remote source")
                warn(f"reinstalling {len(to_update)} module(s) from remotes (index 'version' is ignored)")

            for local_name, remote_key, remote_info in to_update:
                spectral(f"Upgrading {C.CYAN}{remote_key}{C.RESET}…")
                self.do_remove(local_name)
                success, reason = self.repo_mgr.install_module(
                    remote_info, force=True, trust_mgr=self.trust_mgr
                )
                if success:
                    ok(f"Upgraded {remote_key}.")
                    warn(f"UNTRUSTED — run {C.PINK}trust {local_name}{C.RESET} to re-enable.")
                else:
                    err(f"Failed to upgrade {remote_key}: {reason}")
            self.load_modules()
            return

        if cmd == "pack":
            pw = None
            if "--password" in args:
                i = args.index("--password")
                if i + 1 < len(args):
                    pw = args[i + 1]
            positional = [a for a in args[1:] if not a.startswith("--") and a != pw]
            if len(positional) < 2:
                return err("usage: repo pack <src> <output.tar.zst.enc> [--password <pw>]")
            src, outp = positional[0], positional[1]
            if not pw:
                pw = getpass.getpass("  package password: ")
            if not encrypt_package(src, outp, pw):
                return err(f"packing failed: {src}")
            digest = sha256_of_path(outp)
            ok(f"packed {C.CYAN}{src}{C.RESET} → {C.PINK}{outp}{C.RESET}")
            info(f"sha256 : {C.BOLD}{digest}{C.RESET}")
            info("index entry fields:")
            print(f"      {C.GRAY}\"url\"      : \"<host this file>\"{C.RESET}")
            print(f"      {C.GRAY}\"sha256\"  : \"{digest}\"{C.RESET}")
            print(f"      {C.GRAY}\"enc\"     : true{C.RESET}")
            warn("no password in index → install prompts for it (private module)")
            info("add \"password\": \"…\" to the entry to ship it silently (host-obfuscation only)")
            return

        if cmd == "source":
            if len(args) < 2:
                return err("usage: repo source <name>")
            name = self._resolve(args[1])
            if not name:
                return err("Module not installed.")
            mod = self.modules.get(name)
            if mod:
                print(f"\n  {C.PURPLE}╭─ MODULE SOURCE ────────────────────╮{C.RESET}")
                print(f"  {C.PURPLE}│{C.RESET} Module : {name}")
                print(f"  {C.PURPLE}│{C.RESET} Path   : {getattr(mod, '__eidolon_path__', 'Unknown')}")
                print(f"  {C.PURPLE}╰────────────────────────────────────╯\n")
            else:
                print(f"\n  {C.PURPLE}╭─ MODULE SOURCE (UNTRUSTED) ────────╮{C.RESET}")
                print(f"  {C.PURPLE}│{C.RESET} Module : {name}")
                print(f"  {C.PURPLE}│{C.RESET} Path   : {os.path.join(MODULES_DIR, name + '.py')}")
                print(f"  {C.PURPLE}│{C.RESET} Status : {C.YELLOW}{self._untrusted.get(name, 'untrusted')}{C.RESET}")
                print(f"  {C.PURPLE}╰────────────────────────────────────╯\n")
            return

        err("usage: repo [list|add|remove|enable|disable|priority|sync|search|list-modules|stats|check|install|upgrade|update-all|pack|source|info]")

    # ═════════════════════════════════════════════════════════
    # TOFU TRUST COMMANDS (NEW)
    # ═════════════════════════════════════════════════════════
    def do_trust(self, arg):
        """trust <module>|--all — Record hash and enable loading (TOFU)"""
        arg = arg.strip()
        if not arg:
            return err("usage: trust <module> | trust --all")

        if arg == "--all":
            to_trust = []
            for name, status in list(self._untrusted.items()):
                fp = os.path.join(MODULES_DIR, name + ".py")
                if os.path.exists(fp):
                    to_trust.append((name, fp, status))
            if not to_trust:
                return info("nothing to trust")
            warn(f"about to trust {len(to_trust)} module(s):")
            for name, _, status in to_trust:
                warn(f"  · {name} ({status})")
            for name, fp, _ in to_trust:
                h = self.trust_mgr.trust(name, fp)
                ok(f"trusted {C.PINK}{name}{C.RESET} sha256:{h[:16]}…")
            self.load_modules()
            return

        # resolve module key (accepts display name or path)
        name = arg
        if name not in self._untrusted and name not in self.modules:
            resolved = self._resolve(name)
            if resolved:
                name = resolved
            else:
                return err(f"module '{arg}' not found")

        fp = os.path.join(MODULES_DIR, name + ".py")
        if not os.path.exists(fp):
            return err(f"file not found: {fp}")

        prev = self.trust_mgr.get_entry(name) or {}
        prev_status = self._untrusted.get(name, "new")

        h = self.trust_mgr.trust(name, fp)
        ok(f"trusted {C.PINK}{name}{C.RESET}  sha256:{h[:16]}…  (was: {prev_status})")
        if prev_status == "modified" and prev.get("sha256"):
            warn(f"previous hash: {prev['sha256'][:16]}…  — file had been modified")
        self.load_modules()

    def do_untrust(self, arg):
        """untrust <module> — Remove trust entry (module won't load)"""
        name = arg.strip()
        if not name:
            return err("usage: untrust <module>")
        if self.trust_mgr.untrust(name):
            ok(f"untrusted {C.PINK}{name}{C.RESET}")
            self.load_modules()
            return
        resolved = self._resolve(name)
        if resolved and self.trust_mgr.untrust(resolved):
            ok(f"untrusted {C.PINK}{resolved}{C.RESET}")
            self.load_modules()
            return
        warn(f"'{name}' not in trust registry")

    def do_trusted(self, arg):
        """trusted [--all] — List trust registry (default: untrusted only)"""
        show_all = "--all" in arg or "-a" in arg
        entries = self.trust_mgr.list_all()
        if not entries:
            return info("no modules registered — install one first")

        rows = []
        for key, entry in sorted(entries.items()):
            trusted = entry.get("trusted", False)
            if not trusted and not show_all:
                continue
            # live status
            fp = os.path.join(MODULES_DIR, key + ".py")
            live_status = "missing"
            if os.path.exists(fp):
                if trusted:
                    try:
                        live_status = "ok" if sha256_of_path(fp) == entry.get("sha256") else "modified"
                    except OSError:
                        live_status = "unreadable"
                else:
                    live_status = "untrusted"

            color = _TRUST_COLOR.get(live_status, C.WHITE)
            sha = (entry.get("sha256") or "")[:16]
            source = entry.get("source", "?")
            rows.append([
                f"{C.CYAN}{key}{C.RESET}",
                f"{color}{live_status}{C.RESET}",
                f"{sha}…" if sha else "-",
                source,
            ])

        if not rows:
            return info("no trusted modules — use 'trusted --all' to see all registered")

        title = "TRUST REGISTRY (all)" if show_all else "TRUST REGISTRY (untrusted/modified)"
        print_table(["Module", "Status", "SHA256", "Source"], rows, title=title)

    def do_verify(self, arg):
        """verify — Re-check all module hashes against trust registry"""
        results = self.trust_mgr.verify_all()
        if not results:
            return info("no modules registered — nothing to verify")

        problems = {k: v for k, v in results.items() if v != "ok"}
        if not problems:
            return ok(f"all {len(results)} registered module(s) verified (hashes match)")

        rows = []
        for k, status in sorted(problems.items()):
            color = _TRUST_COLOR.get(status, C.WHITE)
            rows.append([f"{C.CYAN}{k}{C.RESET}", f"{color}{status}{C.RESET}"])
        print_table(["Module", "Issue"], rows, title="TRUST VIOLATIONS")
        warn(f"{len(problems)}/{len(results)} module(s) failed — inspect with 'trusted --all'")
        for k, s in problems.items():
            if s == "modified":
                warn(f"{C.PINK}{k}{C.RESET} was modified after trust — run 'trust {k}' to accept or 'remove {k}' to purge")

    # ═════════════════════════════════════════════════════════
    # LOCAL MODULE INSTALL (with destination path)
    # ═════════════════════════════════════════════════════════
    def _do_install_local(self, arg):
        try:
            parts = shlex.split(arg)
        except ValueError as e:
            return err(f"parse error: {e}")

        force = any(p in ("--force", "-f") for p in parts)
        parts = [p for p in parts if p not in ("--force", "-f")]

        if not parts:
            return err("usage: add_module <src> [dest] [--force]")

        src = parts[0]
        dest = parts[1] if len(parts) > 1 else None

        # Resolve source
        src_path = Path(os.path.expanduser(src))
        if not src_path.is_absolute():
            src_path = Path.cwd() / src_path
        if not src_path.exists():
            return err(f"source not found: {src_path}")

        is_dir = src_path.is_dir()
        if not is_dir and not str(src_path).endswith(".py"):
            return err("only .py files or directories allowed")
        if is_dir:
            py_files = [f for f in src_path.rglob("*.py")
                        if not f.name.startswith(("_", "@")) and "__pycache__" not in str(f)]
            if not py_files:
                return err(f"no .py files found in {src_path}")

        # Resolve destination
        if dest:
            dest = dest.replace("\\", "/").strip("/")
            if not dest:
                return err("dest cannot be empty")
            if dest.startswith("/") or ":" in dest.split("/")[0]:
                return err("dest must be a relative path")
            parts_check = dest.split("/")
            if any(p == ".." for p in parts_check):
                return err("dest cannot contain '..'")
            if not is_dir and dest.endswith(".py"):
                dest_rel = dest
            else:
                dest_rel = f"{dest}/{src_path.name}" if is_dir else f"{dest}/{src_path.name}"
        else:
            dest_rel = src_path.name

        installed = []  # (module_key, abs_path, orig_path)

        try:
            if is_dir:
                base_dest = dest_rel.rstrip("/")
                for fsrc in py_files:
                    rel_in_src = fsrc.relative_to(src_path).as_posix()
                    fdest_rel = f"{base_dest}/{rel_in_src}"
                    fdest = Path(MODULES_DIR) / fdest_rel
                    fdest.parent.mkdir(parents=True, exist_ok=True)
                    key = fdest_rel[:-3]
                    if self.trust_mgr.get_entry(key) and not force:
                        warn(f"'{key}' already registered — skipping (use --force)")
                        continue
                    shutil.copy2(fsrc, fdest)
                    installed.append((key, str(fdest), str(fsrc)))
            else:
                dest_path = Path(MODULES_DIR) / dest_rel
                dest_path.parent.mkdir(parents=True, exist_ok=True)
                key = dest_rel[:-3]
                if self.trust_mgr.get_entry(key) and not force:
                    return warn(f"'{key}' already registered — use --force to overwrite")
                shutil.copy2(src_path, dest_path)
                installed.append((key, str(dest_path), str(src_path)))

        except Exception as e:
            return err(f"copy failed: {e}")

        if not installed:
            return warn("nothing installed")

        for key, fp, orig in installed:
            self.trust_mgr.register_untrusted(key, fp, source="local", original=orig)
            ok(f"installed {C.CYAN}{key}{C.RESET} → {os.path.relpath(fp, MODULES_DIR)}")

        warn(f"{len(installed)} module(s) installed but UNTRUSTED")
        warn(f"inspect: {C.PINK}trusted --all{C.RESET}   trust: {C.PINK}trust <path>{C.RESET}")
        self.load_modules()

    # ═══════════════════════════════════════════════════════════════════
    # MODULE SCAFFOLDING (new_module)
    # ═══════════════════════════════════════════════════════════════════
    def do_new_module(self, arg):
        """new_module <name> [dir] — Scaffold a guided module skeleton"""
        args = arg.strip().split()
        if not args:
            return err("usage: new_module <name> [target_dir]")

        raw_name = args[0].strip("/")
        if not raw_name:
            return err("module name cannot be empty")
        parts = [p for p in raw_name.split("/") if p and p != "."]
        if not parts or any(p == ".." for p in parts):
            return err(f"invalid module name: {raw_name!r}")
        for p in parts:
            if not all(ch.isalnum() or ch in "_-" for ch in p):
                return err(f"invalid characters in name (letters, digits, _ or - only): {raw_name!r}")

        base    = parts[-1]
        rel_key = "/".join(parts)

        if len(args) > 1:
            target_dir  = os.path.expanduser(args[1])
            target_file = os.path.join(target_dir, base + ".py")
            external    = True
        else:
            target_file = os.path.join(MODULES_DIR, rel_key + ".py")
            external    = False

        if os.path.exists(target_file):
            return err(f"already exists: {target_file}")

        category = parts[0] if len(parts) > 1 else "custom"
        content = (_NEW_MODULE_TEMPLATE
                   .replace("__NAME__", base)
                   .replace("__CATEGORY__", category)
                   .replace("__TYPE__", "generic")
                   .replace("__AUTHOR__", self.operator_name))

        try:
            os.makedirs(os.path.dirname(target_file) or ".", exist_ok=True)
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(content)
        except OSError as e:
            return err(f"cannot write module: {e}")

        if not external:
            self.trust_mgr.register_untrusted(rel_key, target_file, source="local")
            ok(f"scaffolded {C.CYAN}{rel_key}{C.RESET} → {target_file}")
            warn("module is UNTRUSTED (TOFU)")
            info(f"edit it, then: {C.PINK}trust {rel_key}{C.RESET}  →  {C.PINK}use {rel_key}{C.RESET}  →  {C.PINK}run{C.RESET}")
        else:
            ok(f"scaffolded {C.CYAN}{base}{C.RESET} → {target_file}")
            warn(f"outside the modules dir — it will NOT be auto-loaded; move it under {MODULES_DIR}")
        self.load_modules()

    def do_add_module(self, arg):
        """add_module <src> [dest] [--force] — Install local module (TOFU: untrusted until trusted)"""
        return self._do_install_local(arg)

    def do_install_local(self, arg):
        """install_local <src> [dest] [--force] — Same as add_module"""
        return self._do_install_local(arg)

    # ═════════════════════════════════════════════════════════
    # MODULE MANAGEMENT
    # ═════════════════════════════════════════════════════════
    def do_remove(self, arg):
        """remove <module_name> — Physically delete a module (also untrusts)"""
        name = self._resolve(arg.strip())
        if not name:
            return err(f"module '{arg.strip()}' not found.")

        # Physically delete
        mod_path = getattr(self.modules.get(name), "__eidolon_path__", None) if name in self.modules else None
        if not mod_path:
            mod_path = os.path.join(MODULES_DIR, name + ".py")

        if not os.path.exists(mod_path):
            return err(f"file not found: {mod_path}")

        abs_mod_path = os.path.abspath(mod_path)
        abs_modules_dir = os.path.abspath(MODULES_DIR)
        if not abs_mod_path.startswith(abs_modules_dir):
            return err("Security violation: attempted to delete outside modules dir")

        try:
            os.remove(abs_mod_path)
            self.trust_mgr.untrust(name)
            ok(f"Removed module: {C.PINK}{name}{C.RESET}")
            parent_dir = os.path.dirname(abs_mod_path)
            while parent_dir != abs_modules_dir and os.path.exists(parent_dir) and not os.listdir(parent_dir):
                os.rmdir(parent_dir)
                parent_dir = os.path.dirname(parent_dir)
            if self.current_name == name: self.do_back("")
            self.load_modules()
        except Exception as e:
            err(f"failed to remove module: {e}")

    def do_help(self, arg):
        """help [cmd] — show help"""
        arg = arg.strip()
        if arg:
            meth = getattr(self, f"do_{arg}", None)
            if not meth: return err(f"no such command: {arg}")
            print(f"\n  {C.PINK}{arg}{C.RESET}  —  {(meth.__doc__ or '').strip().splitlines()[0]}\n")
            return

        print(f"\n{C.PURPLE}╭─────────────────────────────────────────╮{C.RESET}")
        print(f"{C.PURPLE}│{C.RESET}  {C.PINK}EIDOLON{C.RESET} {C.GRAY}·{C.RESET} {C.CYAN}{CODENAME}{C.RESET} {C.GRAY}·{C.RESET} reference")
        print(f"{C.PURPLE}╰─────────────────────────────────────────╯{C.RESET}")
        print(f"  {C.CYAN}help{C.RESET} / {C.CYAN}clear{C.RESET} / {C.CYAN}banner{C.RESET} / {C.CYAN}reload{C.RESET} / {C.CYAN}exit{C.RESET}")
        print(f"  {C.CYAN}modules{C.RESET} / {C.CYAN}ls{C.RESET} [--all] / {C.CYAN}search{C.RESET} <kw> / {C.CYAN}info{C.RESET} <name>")
        print(f"  {C.CYAN}use{C.RESET} <name> / {C.CYAN}back{C.RESET} / {C.CYAN}options{C.RESET} / {C.CYAN}set{C.RESET} <k> <v> / {C.CYAN}run{C.RESET}")
        print(f"  {C.CYAN}deps{C.RESET} <name> — show module pip requirements (never auto-installed)")
        print(f"  {C.PINK}── TOFU ──{C.RESET}")
        print(f"  {C.CYAN}trust{C.RESET} <module>|--all    · {C.CYAN}untrust{C.RESET} <module>")
        print(f"  {C.CYAN}trusted{C.RESET} [--all]          · {C.CYAN}verify{C.RESET}")
        print(f"  {C.PINK}── REPO ──{C.RESET}")
        print(f"  {C.CYAN}repo{C.RESET} <list|add|remove|enable|disable|priority|sync|search|list-modules|stats|check|install|upgrade|update-all|pack|source|info>")
        print(f"  {C.PINK}── LOCAL ──{C.RESET}")
        print(f"  {C.CYAN}new_module{C.RESET} <name> [dir]      — scaffold a guided module skeleton")
        print(f"  {C.CYAN}add_module{C.RESET} <src> [dest] [--force]")
        print(f"  {C.CYAN}install_local{C.RESET} <src> [dest] [--force]")
        print(f"  {C.CYAN}remove{C.RESET} <name> / {C.CYAN}setg{C.RESET} <k> <v> / {C.CYAN}globals{C.RESET}")
        print(f"  {C.PINK}── C2 (WRAITH KERNEL) ──{C.RESET}")
        print(f"  {C.CYAN}gen{C.RESET} <module> [k=v ...]   — build a payload / start a listener as a job")
        print(f"  {C.CYAN}jobs{C.RESET} / {C.CYAN}kill <id>{C.RESET}          — background jobs · {C.CYAN}c2{C.RESET} <status|sessions|payloads>\n")

    def do_banner(self, arg): print_banner(animate=True)
    def do_clear(self, arg): os.system("cls" if os.name == "nt" else "clear")

    def do_reload(self, arg):
        """reload — rescan workspace modules (TOFU re-check)"""
        if self._subshell_active: self.exit_subshell()
        spectral("reloading module arsenal (TOFU verification)…")
        self.current = self.current_name = self.current_options = None
        self.load_modules()
        ok("arsenal reloaded")

    def do_status(self, arg):
        """status — show operator status"""
        sessions = self.db.get_sessions()
        active = sum(1 for s in sessions if s["status"] == "active")
        trust_entries = self.trust_mgr.list_all()
        trusted_ct = sum(1 for e in trust_entries.values() if e.get("trusted"))
        print(f"\n  {C.PURPLE}╭─ OPERATOR STATUS ──────────────────╮{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  name      : {C.BOLD}{self.operator_name}{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  team      : {C.CYAN}{self.operator_team}{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  uptime    : {_uptime_str(self.session_t0)}")
        print(f"  {C.PURPLE}│{C.RESET}  workspace : {C.GREEN}{WORKSPACE_DIR}{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  modules   : {C.GREEN}{len(self.modules)}{C.RESET} loaded / {C.YELLOW}{len(self._untrusted)}{C.RESET} untrusted")
        print(f"  {C.PURPLE}│{C.RESET}  trust     : {C.GREEN}{trusted_ct}{C.RESET} trusted / {len(trust_entries)} registered")
        print(f"  {C.PURPLE}│{C.RESET}  sessions  : {C.GREEN}{active}{C.RESET} active")
        print(f"  {C.PURPLE}╰────────────────────────────────────╯\n")

    def do_exit(self, arg):
        """exit / quit — leave tool"""
        try:
            stopped = self.jobs.shutdown_all()
        except Exception:
            stopped = 0
        if stopped:
            spectral(f"{stopped} background job(s) shut down")
        if self._subshell_active:
            self.exit_subshell(); ok("returned to Eidolon"); return False
        print(f"\n  {C.PURPLE}╰─{C.RESET} {C.CYAN}eidolon out.{C.RESET}  {C.GRAY}uptime: {_uptime_str(self.session_t0)}{C.RESET}\n")
        return True

    do_quit = do_exit

    def do_modules(self, arg):
        """modules [--all] — List arsenal (default: trusted only)"""
        show_all = "--all" in arg or "-a" in arg

        if not self.modules and not (show_all and self._untrusted):
            return warn("no modules loaded.")

        rows = []
        # Trusted (loaded) modules
        for i, (name, m) in enumerate(sorted(self.modules.items()), 1):
            ver = getattr(m, "VERSION", "0.0.0")
            rows.append([
                f"{C.PURPLE}{i:02d}{C.RESET}",
                f"{C.CYAN}{name}{C.RESET}",
                ver,
                _type_label(m),
                getattr(m, "CATEGORY", "-"),
                f"{C.GREEN}trusted{C.RESET}",
                str(getattr(m, "DESCRIPTION", "-"))[:24],
            ])

        # Untrusted modules (blocked)
        if show_all and self._untrusted:
            for name, status in sorted(self._untrusted.items()):
                color = _TRUST_COLOR.get(status, C.YELLOW)
                rows.append([
                    f"{C.GRAY}--{C.RESET}",
                    f"{C.GRAY}{name}{C.RESET}",
                    "-", "-", "-",
                    f"{color}{status}{C.RESET}",
                    f"{C.GRAY}blocked by TOFU{C.RESET}",
                ])

        title = f"EIDOLON ARSENAL ({len(self.modules)} loaded"
        if show_all and self._untrusted:
            title += f" · {len(self._untrusted)} untrusted"
        title += ")"
        print_table(["#", "Arsenal", "Ver", "Type", "Category", "Trust", "Description"], rows, title=title)
    do_ls = do_modules

    def do_search(self, arg):
        kw = arg.strip().lower()
        if not kw: return err("usage: search <keyword>")
        hits = []
        for name, m in self.modules.items():
            if kw in (name + str(getattr(m, "DESCRIPTION", ""))).lower():
                hits.append((name, "trusted"))
        for name in self._untrusted:
            if kw in name.lower():
                hits.append((name, "untrusted"))
        if not hits: return warn("no matches.")
        for h, status in sorted(hits):
            marker = f"{C.GREEN}●{C.RESET}" if status == "trusted" else f"{C.YELLOW}○{C.RESET}"
            print(f"     {marker} {h}  {C.GRAY}[{status}]{C.RESET}")

    def do_info(self, arg):
        name = self._resolve(arg)
        if not name:
            return err(f"not found: '{arg.strip()}'")

        # Untrusted path
        if name in self._untrusted and name not in self.modules:
            status = self._untrusted[name]
            entry = self.trust_mgr.get_entry(name) or {}
            fp = os.path.join(MODULES_DIR, name + ".py")
            print(f"\n  {C.PURPLE}╭─ MODULE INTEL (UNTRUSTED) ─────────╮{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET} name  : {C.CYAN}{name}{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET} status: {_TRUST_COLOR.get(status, C.YELLOW)}{status}{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET} file  : {fp}")
            if entry.get("sha256"):
                print(f"  {C.PURPLE}│{C.RESET} sha256: {entry['sha256'][:24]}…")
            if entry.get("source"):
                print(f"  {C.PURPLE}│{C.RESET} source: {entry['source']}")
            if entry.get("original"):
                print(f"  {C.PURPLE}│{C.RESET} orig  : {entry['original']}")
            print(f"  {C.PURPLE}╰────────────────────────────────────╯")
            info(f"run {C.PINK}trust {name}{C.RESET} to inspect or use")
            return

        # Trusted path
        m = self.modules[name]
        entry = self.trust_mgr.get_entry(name) or {}
        print(f"\n  {C.PURPLE}╭─ MODULE INTEL ─────────────────────╮{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET} name: {c(name, C.WHITE)}")
        print(f"  {C.PURPLE}│{C.RESET} ver : {getattr(m, 'VERSION', '0.0.0')} | type: {_type_label(m)} | cat: {getattr(m,'CATEGORY','-')}")
        print(f"  {C.PURPLE}│{C.RESET} desc: {getattr(m,'DESCRIPTION','-')}")
        print(f"  {C.PURPLE}│{C.RESET} file: {getattr(m,'__eidolon_path__','?')}")
        print(f"  {C.PURPLE}│{C.RESET} trust: {C.GREEN}verified{C.RESET} (sha256: {(entry.get('sha256') or '?')[:16]}…)")
        print(f"  {C.PURPLE}╰────────────────────────────────────╯")
        opts = getattr(m, "OPTIONS", {})
        if opts:
            rows = [[k, str(v.get("value", "")), "yes" if v.get("required") else "no", v.get("kind", ""), v.get("desc", "")] for k, v in opts.items()]
            print_table(["Name", "Default", "Req", "Kind", "Desc"], rows, title="OPTIONS")
        reqs = [str(r) for r in (getattr(m, "REQUIREMENTS", None) or [])]
        if reqs:
            missing = _missing_requirements(reqs)
            shown = ", ".join(f"{C.RED}{r}{C.RESET}" if r in missing else r for r in reqs)
            print(f"  {C.PURPLE}│{C.RESET} reqs : {shown}")
            warn(f"requirements are NOT auto-installed — see: {C.PINK}deps {name}{C.RESET}")
        print()

    def do_use(self, arg):
        name = self._resolve(arg)
        if not name:
            raw = arg.strip()
            if raw in self._untrusted:
                status = self._untrusted[raw]
                return err(f"module '{raw}' is {status}. run {C.PINK}trust {raw}{C.RESET} first.")
            return err(f"module '{arg.strip()}' not found.")
        if name not in self.modules:
            status = self._untrusted.get(name, "untrusted")
            return err(f"module '{name}' is {status}. run {C.PINK}trust {name}{C.RESET} first.")
        mod = self.modules[name]
        self.current = mod
        self.current_name = name
        self.current_options = copy.deepcopy(getattr(mod, "OPTIONS", {}))
        ok(f"selected: {c(name, C.PINK)}")
        reqs = getattr(mod, "REQUIREMENTS", None) or []
        missing = _missing_requirements(reqs)
        if missing:
            warn(f"missing requirements: {', '.join(missing)} — see {C.PINK}deps {name}{C.RESET}")
        self.do_options("")

    def do_back(self, arg):
        if self._subshell_active: self.exit_subshell()
        if not self.current: return warn("no module selected.")
        spectral(f"left {self.current_name}")
        self.current = self.current_name = self.current_options = None

    def do_options(self, arg):
        if not self.current: return err("no module selected.")
        opts = self.current_options or {}
        if not opts: return info("no options.")
        rows = [[k, str(v.get("value", "")), "yes" if v.get("required") else "no", v.get("kind", ""), v.get("desc", "")] for k, v in opts.items()]
        print_table(["Name", "Value", "Req", "Kind", "Desc"], rows, title=f"OPTIONS · {self.current_name}")

    def do_show(self, arg):
        a = arg.strip().lower()
        if a in ("options", "opt", "o", ""): self.do_options("")
        elif a in ("modules", "m"): self.do_modules("")
        else: err("usage: show [options|modules]")

    @staticmethod
    def _cast(value, reference):
        s = value.strip()
        if isinstance(reference, bool): return s.lower() in ("1", "true", "yes", "on", "y")
        if isinstance(reference, int) and not isinstance(reference, bool):
            try: return int(s)
            except ValueError: return s
        if isinstance(reference, float):
            try: return float(s)
            except ValueError: return s
        return s

    def do_set(self, arg):
        if not self.current: return err("no module selected.")
        try: parts = shlex.split(arg)
        except ValueError as e: return err(f"parse error: {e}")
        if len(parts) < 2: return err("usage: set <name> <value>")
        key, val = parts[0], " ".join(parts[1:])
        if key not in self.current_options: return err(f"unknown option: {key}")
        old = self.current_options[key].get("value")
        self.current_options[key]["value"] = self._cast(val, old)
        spec = self.current_options[key]
        if spec.get("kind") == "payload" and str(val).strip():
            try:
                from wraith import store
                _, manifest = store.resolve_payload(str(spec["value"]), kinds=spec.get("types") or None)
            except ImportError as e:
                self.current_options[key]["value"] = old
                return err(f"payload subsystem unavailable: {e}")
            except ValueError as e:
                self.current_options[key]["value"] = old
                return err(f"payload rejected — {e}")
            ok(f"{C.CYAN}{key}{C.RESET} → {spec['value']!r}  ({store.summary(manifest)})")
            return
        ok(f"{C.CYAN}{key}{C.RESET} → {self.current_options[key]['value']!r}")

    def do_unset(self, arg):
        key = arg.strip()
        if not self.current or key not in (self.current_options or {}): return err(f"unknown: {key}")
        default = getattr(self.current, "OPTIONS", {}).get(key, {}).get("value", "")
        self.current_options[key]["value"] = copy.deepcopy(default)
        spectral(f"{key} reset to default")

    def do_run(self, arg):
        if not self.current: return err("no module selected.")
        # Re-verify trust right before exec (paranoia)
        name = self.current_name
        fp = getattr(self.current, "__eidolon_path__", None)
        if fp and os.path.exists(fp):
            trusted, status = self.trust_mgr.is_trusted(name, fp)
            if not trusted:
                return err(f"module '{name}' is {status} — refusing to run. run 'trust {name}'.")

        missing = [k for k, v in (self.current_options or {}).items() if v.get("required") and v.get("value") in (None, "", [], {})]
        if missing: return err(f"missing required: {', '.join(missing)}")

        values = {k: v.get("value") for k, v in self.current_options.items()}
        values, payload_error = self._resolve_payload_values(values)
        if payload_error:
            return err(f"payload option rejected — {payload_error}")
        if "--bg" in (arg or "").split() or _module_type(self.current) == MODULE_TYPE_LISTENER:
            job = self.jobs.submit(self.current, self.current_name, values)
            ok(f"job #{job.jid} started — {self.current_name} (background)")
            info(f"manage: {C.CYAN}jobs{C.RESET} · stop with {C.CYAN}kill {job.jid}{C.RESET}")
            return
        hr(C.PURPLE)
        print(f"  {C.PINK}◈{C.RESET} {C.BOLD}EXECUTING OPERATION{C.RESET}")
        print(f"  {C.SHADOW}├─{C.RESET} module : {C.PINK}{self.current_name}{C.RESET}")
        hr(C.PURPLE)
        try: self.current.run(values)
        except KeyboardInterrupt: warn("interrupted.")
        except Exception as e:
            err(f"module error: {e}")
            if os.environ.get("EIDOLON_DEBUG"): traceback.print_exc()
        if not self._subshell_active:
            hr(C.PURPLE); ok("operation complete")

    def do_deps(self, arg):
        """deps <module> — Show module pip requirements (printed, never installed)"""
        name = self._resolve(arg.strip())
        if not name or name not in self.modules:
            return err(f"module '{arg.strip()}' not found or not loaded")
        reqs = [str(r) for r in (getattr(self.modules[name], "REQUIREMENTS", None) or [])]
        if not reqs:
            return info(f"'{name}' declares no REQUIREMENTS")
        missing = _missing_requirements(reqs)
        rows = [[r, f"{C.RED}missing{C.RESET}" if r in missing else f"{C.GREEN}present{C.RESET}"] for r in reqs]
        print_table(["Requirement", "Status"], rows, title=f"REQUIREMENTS · {name}")
        warn("the framework never installs anything automatically (security)")
        info(f"install manually: {C.BOLD}pip install {' '.join(reqs)}{C.RESET}")

    def do_gen(self, arg):
        """gen <module> [key=value ...] — parameterized generation.
        payload-type  → builds the artifact and reports what hit the store
        listener-type → starts in the background as a managed job
        """
        try:
            parts = shlex.split(arg or "")
        except ValueError as e:
            return err(f"parse error: {e}")
        if not parts:
            return err("usage: gen <module> [key=value ...]")
        name = self._resolve(parts[0])
        if not name or name not in self.modules:
            return err(f"module '{parts[0]}' not found or not loaded — see: {C.CYAN}modules{C.RESET}")
        mod = self.modules[name]
        mtype = _module_type(mod)
        if mtype not in (MODULE_TYPE_PAYLOAD, MODULE_TYPE_LISTENER):
            return err(f"'{name}' is a '{mtype}' module — gen works on payload (builders) and listener modules")
        opts = copy.deepcopy(getattr(mod, "OPTIONS", {}))
        for tok in parts[1:]:
            if "=" not in tok:
                return err(f"bad parameter {tok!r} — use key=value")
            k, _, v = tok.partition("=")
            if k not in opts:
                return err(f"unknown option: {k} — declared options: {', '.join(opts) or '(none)'}")
            opts[k]["value"] = self._cast(v, opts[k].get("value"))
        for k, v in opts.items():
            if not (v.get("required") and v.get("value") in (None, "", [], {})):
                continue
            try:
                reply = input(f"  ? {k} [{v.get('desc', '')}]: ").strip()
            except (EOFError, KeyboardInterrupt):
                return err("aborted — missing required parameter")
            if not reply:
                return err(f"aborted — missing required parameter: {k}")
            opts[k]["value"] = self._cast(reply, opts[k].get("value"))
        values = {k: v.get("value") for k, v in opts.items()}
        values, payload_error = self._resolve_payload_values(values, module=mod)
        if payload_error:
            return err(f"payload option rejected — {payload_error}")
        if mtype == MODULE_TYPE_LISTENER:
            job = self.jobs.submit(mod, name, values)
            ok(f"job #{job.jid} started — {name} (background listener)")
            info(f"manage: {C.CYAN}jobs{C.RESET} · stop with {C.CYAN}kill {job.jid}{C.RESET}")
            return
        try:
            from wraith import store as wstore
            before = set(wstore.list_payloads())
        except ImportError:
            before = None
        hr(C.PURPLE)
        print(f"  {C.PINK}◈{C.RESET} {C.BOLD}GENERATING PAYLOAD{C.RESET}")
        print(f"  {C.SHADOW}├─{C.RESET} builder: {C.PINK}{name}{C.RESET}")
        hr(C.PURPLE)
        try:
            mod.run(values)
        except KeyboardInterrupt:
            warn("interrupted.")
        except Exception as e:
            err(f"builder error: {e}")
            if os.environ.get("EIDOLON_DEBUG"):
                traceback.print_exc()
            return
        if before is not None:
            try:
                from wraith import store as wstore
                for n, manifest in wstore.list_payloads().items():
                    if n in before:
                        continue
                    info(f"registered payload: {C.CYAN}{n}{C.RESET} — {wstore.summary(manifest)}")
            except ImportError:
                pass
        if not self._subshell_active:
            hr(C.PURPLE)
            ok("generation complete")

    def do_jobs(self, arg):
        """jobs — list background jobs (listeners, long-running modules)"""
        jobs = self.jobs.all()
        if not jobs:
            return info("no background jobs — listener modules started with gen appear here")
        marks = {"running": (C.GREEN, "●"), "done": (C.GRAY, "○"), "exited": (C.GRAY, "○"),
                 "stopped": (C.GRAY, "○"), "failed": (C.RED, "✗")}
        rows = []
        for j in jobs:
            color, mark = marks.get(j.status, (C.YELLOW, "○"))
            rows.append([f"{C.PINK}#{j.jid}{C.RESET}", f"{C.CYAN}{j.name}{C.RESET}",
                         f"{color}{mark} {j.status}{C.RESET}", _uptime_str(j.started),
                         (j.error or "-")[:40]])
        print_table(["ID", "Module", "Status", "Uptime", "Error"], rows, title="BACKGROUND JOBS")
        info(f"stop one with: {C.PINK}kill <id>{C.RESET}")

    def do_kill(self, arg):
        """kill <id> — stop a background job (calls the module's stop())"""
        token = arg.strip().lstrip("#")
        if not token.isdigit():
            return err("usage: kill <job id> — see: jobs")
        okk, msg = self.jobs.kill(int(token))
        (ok if okk else err)(msg)

    def _payload_specs(self, options):
        """Option specs declared as "kind": "payload" — the dedicated payload
        field. These resolve against the typed wraith store: `set KEY <ref>`
        validates live, run() receives a manifest dict with a "path" key.
        """
        return {k: v for k, v in (options or {}).items() if v.get("kind") == "payload"}

    def _resolve_payload_values(self, values, module=None):
        """Swap every payload-kind option's raw ref (store name or path) for
        its manifest dict (+ path). Returns (values, error_or_None).
        """
        specs = self._payload_specs(getattr(module or self.current, "OPTIONS", {}))
        if not specs:
            return values, None
        try:
            from wraith import store
        except ImportError as e:
            return values, f"payload subsystem unavailable: {e}"
        for key, meta in specs.items():
            ref = str(values.get(key) or "").strip()
            if not ref:
                continue
            try:
                path, manifest = store.resolve_payload(ref, kinds=meta.get("types") or None)
            except ValueError as e:
                return values, f"{key}: {e}"
            values[key] = dict(manifest, path=path)
        return values, None

    @property
    def wraith_listener(self):
        """The running wraith Listener (or None). Payload-builder modules
        read the operator profile from here: EIDOLON_SHELL.wraith_listener
        gives .url / .token / .tags of the listener that is up right now.
        Listener modules assign themselves here at start().
        """
        return getattr(self, "_wraith_listener", None)

    @wraith_listener.setter
    def wraith_listener(self, value):
        """Listener modules publish their operating profile: any object (or
        simple namespace) that carries .url / .token / .tags."""
        self._wraith_listener = value

    # ── WRAITH C2 subsystem ───────────────────────────────────────────────────────────
    def _c2_on_event(self, event):
        kind, sess = event
        lock = getattr(self, "_wraith_lock", None)
        with (lock or threading.RLock()):
            if kind == "up":
                line = (f"  {C.GREEN}⬢{C.RESET} {C.BOLD}payload connected{C.RESET} "
                        f"{C.PINK}{sess.sid[:8]}{C.RESET} {C.GRAY}·{C.RESET} "
                        f"{sess.user}@{sess.host} {C.GRAY}·{C.RESET} "
                        f"{sess.implant}/{sess.os}-{sess.arch} {C.GRAY}·{C.RESET} {sess.addr}")
            else:
                line = (f"  {C.YELLOW}◌{C.RESET} {C.GRAY}session lost{C.RESET} "
                        f"{C.PINK}{sess.sid[:8]}{C.RESET} {C.GRAY}·{C.RESET} {sess.label}")
            try:
                print(f"\r{line}{C.RESET}")
                if not self._subshell_active:
                    print(self.prompt, end="", flush=True)
            except Exception:
                pass

    def do_c2(self, arg):
        """c2 <status|sessions|payloads> — read-only view over the C2 kernel
        (the framework ships no listener: listener modules are started with gen)"""
        try:
            from wraith import protocol
            from wraith import store
            from wraith import sessions as wsessions
        except ImportError as e:
            return err(f"c2 kernel unavailable: {e}")

        parts = shlex.split(arg or "")
        sub = parts[0] if parts else ""

        if not sub or sub == "help":
            print(f"\n  {C.PURPLE}╭─ WRAITH C2 ──────────────────────────╮{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  {C.CYAN}c2 status{C.RESET}                 — listener profile + session counts")
            print(f"  {C.PURPLE}│{C.RESET}  {C.CYAN}c2 sessions{C.RESET}               — live session table")
            print(f"  {C.PURPLE}│{C.RESET}  {C.CYAN}c2 payloads{C.RESET}               — list the typed payload store")
            print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}listeners + builders are MODULES (module types 'listener' / 'payload'):{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}the framework ships none — write or install one, then:{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  {C.CYAN}gen <listener module> [k=v ...]{C.RESET}{C.GRAY} → background job · managed by {C.CYAN}jobs{C.RESET}{C.GRAY} / {C.CYAN}kill{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  {C.CYAN}gen <payload module>  [k=v ...]{C.RESET}{C.GRAY} → artifact lands in the typed store{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}builders read the listener profile from {C.CYAN}EIDOLON_SHELL.wraith_listener{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  {C.GRAY}tags handshake: payload and listener must share a protocol tag (4403){C.RESET}")
            print(f"  {C.PURPLE}╰────────────────────────────{C.RESET}\n")
            return

        if sub == "status":
            reg = wsessions.default_registry()
            counts = reg.counts()
            lsn = self.wraith_listener
            print(f"\n  {C.PURPLE}╭─ WRAITH STATUS ──────────────────────╮{C.RESET}")
            if lsn is not None:
                tags = " ".join(getattr(lsn, "tags", ()) or ()) or "-"
                print(f"  {C.PURPLE}│{C.RESET}  listener : {C.GREEN}● online{C.RESET}  {getattr(lsn, 'url', '?')}")
                print(f"  {C.PURPLE}│{C.RESET}  tags     : {C.CYAN}{tags}{C.RESET} {C.GRAY}(payloads must share one){C.RESET}")
            else:
                print(f"  {C.PURPLE}│{C.RESET}  listener : {C.GRAY}○ none — start a listener module: {C.CYAN}gen <listener module>{C.RESET}")
            active_jobs = len(self.jobs.active())
            print(f"  {C.PURPLE}│{C.RESET}  jobs     : {C.CYAN}{active_jobs}{C.RESET} running · see {C.CYAN}jobs{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET}  sessions : {C.GREEN}{counts['active']}{C.RESET} active · {C.YELLOW}{counts['lost']}{C.RESET} lost · {counts['total']} total")
            print(f"  {C.PURPLE}│{C.RESET}  store    : {C.CYAN}{store.STORE_DIR}{C.RESET}")
            print(f"  {C.PURPLE}╰───────────────────────────────────╰\n{C.RESET}")
            return

        if sub == "sessions":
            reg = wsessions.default_registry()
            rows = []
            for s in reg.all():
                mark = f"{C.GREEN}●{C.RESET}" if s.status == "active" else f"{C.GRAY}○{C.RESET}"
                rows.append([mark, f"{C.PINK}{s.sid[:8]}{C.RESET}", f"{s.user}@{s.host}",
                             f"{s.implant}/{s.os}-{s.arch}", s.addr,
                             _uptime_str(s.connected_at)])
            if not rows:
                return info("no sessions yet — gen a listener module, then deliver an artifact.")
            print_table(["", "SID", "Identity", "Implant", "Address", "Uptime"], rows,
                        title="WRAITH SESSIONS")
            return

        if sub == "payloads":
            payloads = store.list_payloads()
            if not payloads:
                return info("payload store empty — a payload-type module fills it via store.register_payload()")
            rows = []
            for p in payloads.values():
                rows.append([C.PINK + p["name"] + C.RESET, p.get("type", "?"),
                             p.get("protocol") or "-",
                             p.get("backend") or "-",
                             (f"{p['os']}/{p['arch']}" if p.get("os") else "-"),
                             (p.get("sha256") or "")[:12]])
            print_table(["Name", "Type", "Protocol", "Backend", "OS/Arch", "SHA256"], rows,
                        title=f"PAYLOAD STORE · {store.STORE_DIR}")
            return

        return err(f"unknown c2 subcommand: {sub!r} — try {C.CYAN}c2{C.RESET} for help")

    def do_sessions(self, arg):
        arg = arg.strip()
        if arg:
            try: sid = int(arg.lstrip("#"))
            except ValueError: return err(f"invalid id: {arg!r}")
            s = self.db.get_session(sid)
            if not s: return err(f"session #{sid} not found")
            print(f"\n  {C.PURPLE}╭─ SESSION #{sid} ─────────────────────╮{C.RESET}")
            print(f"  {C.PURPLE}│{C.RESET} module : {s['module']}")
            print(f"  {C.PURPLE}│{C.RESET} target : {s['target']}")
            print(f"  {C.PURPLE}│{C.RESET} status : {s['status']}")
            print(f"  {C.PURPLE}╰──────────────────────────────────────╯\n")
            return

        sessions = self.db.get_sessions()
        if not sessions: return info("no sessions recorded.")
        rows = []
        for s in sessions:
            status = f"{C.GREEN}● active{C.RESET}" if s["status"] == "active" else f"{C.GRAY}○ closed{C.RESET}"
            end = s.get("closed_at") or time.time()
            dur = _fmt_duration(end - s.get("started_at", end))
            rows.append([f"{C.PINK}#{s['id']}{C.RESET}", s["module"], s.get("target","-"), status, dur])
        print_table(["ID", "Module", "Target", "Status", "Duration"], rows, title="SESSIONS")

    def do_setg(self, arg):
        try: parts = shlex.split(arg)
        except ValueError as e: return err(f"parse error: {e}")
        if len(parts) < 2: return err("usage: setg <name> <value>")
        key, val = parts[0], " ".join(parts[1:])
        self.globals[key] = val
        self.db.set_global(key, val)
        ok(f"global {C.CYAN}{key}{C.RESET} → {val!r} (saved to DB)")

    def do_globals(self, arg):
        if not self.globals: return info("no globals set.")
        rows = [[k, v] for k, v in self.globals.items()]
        print_table(["Name", "Value"], rows, title="GLOBAL VARIABLES")

    # ═════════════════════════════════════════════════════════
    # TAB COMPLETION
    # ═════════════════════════════════════════════════════════
    def complete_new_module(self, text, line, begidx, endidx):
        parts = line.split()
        in_first = (len(parts) == 1) or (len(parts) == 2 and not line.endswith(" "))
        if in_first:
            # completing the module name: existing category dirs under MODULES_DIR
            prefix   = text
            sub_path = ""
            if "/" in prefix:
                sub_path, _, sub = prefix.rpartition("/")
                sub_path = sub_path.strip("/")
                sub = text.rpartition("/")[2]
            else:
                sub = prefix
            base_dir = os.path.join(MODULES_DIR, sub_path) if sub_path else MODULES_DIR
            try:
                entries = os.listdir(base_dir)
            except OSError:
                return []
            results = []
            for e in sorted(entries):
                if e.startswith((".", "_", "@")):
                    continue
                full = os.path.join(base_dir, e)
                if os.path.isdir(full) and e.startswith(sub):
                    results.append((sub_path + "/" if sub_path else "") + e + "/")
            return results
        # completing the optional target dir: filesystem directories
        clean_text = text.strip("'\"")
        expanded   = os.path.expanduser(clean_text) if clean_text else ""
        matches    = glob.glob(expanded + "*") if expanded else []
        results    = []
        for match in matches:
            if not os.path.isdir(match):
                continue
            display = match
            if clean_text.startswith("~") and not display.startswith("~"):
                home = os.path.expanduser("~")
                if display.startswith(home):
                    display = "~" + display[len(home):]
            if not display.endswith("/"):
                display += "/"
            results.append(display)
        return results

    def complete_add_module(self, text, line, begidx, endidx):
        clean_text = text.strip("'\"")
        expanded_text = os.path.expanduser(clean_text)
        matches = glob.glob(expanded_text + '*')
        results = []
        for match in matches:
            basename = os.path.basename(match.rstrip('/'))
            if basename == '__pycache__' or basename.startswith('_'): continue
            is_dir = os.path.isdir(match)
            if is_dir or match.endswith('.py'):
                display_match = match
                if clean_text.startswith('~'):
                    home = os.path.expanduser('~')
                    if display_match.startswith(home): display_match = '~' + display_match[len(home):]
                if is_dir and not display_match.endswith('/'): display_match += '/'
                if text.startswith("'") and not display_match.startswith("'"): display_match = "'" + display_match + "'"
                elif text.startswith('"') and not display_match.startswith('"'): display_match = '"' + display_match + '"'
                results.append(display_match)
        return results
    complete_install_local = complete_add_module

    def complete_remove(self, text, *_):
        known = list(self.modules.keys()) + list(self._untrusted.keys())
        return [m for m in known if m.startswith(text)]
    def complete_trust(self, text, *_):
        if text == "--": return ["--all"]
        return [m for m in self._untrusted if m.startswith(text)]

    def complete_untrust(self, text, *_):
        entries = self.trust_mgr.list_all()
        return [m for m in entries if m.startswith(text)]

    def complete_trusted(self, text, *_):
        return [x for x in ["--all"] if x.startswith(text)]

    def complete_repo(self, text, line, begidx, endidx):
        parts = line.split()
        if line.endswith(' '): parts.append('')
        if len(parts) == 2:
            cmds = ["list", "add", "remove", "enable", "disable", "priority",
                    "sync", "search", "list-modules", "stats", "check",
                    "install", "upgrade", "update-all", "pack", "source", "info"]
            return [c for c in cmds if c.startswith(text)]
        elif len(parts) == 3:
            if parts[1] in ('install', 'info', 'upgrade', 'source', 'search'):
                try: return [m for m in self.repo_mgr.get_all_modules() if m.startswith(text)]
                except Exception: return []
            elif parts[1] in ('enable', 'disable', 'remove', 'priority'):
                return [r['url'] for r in self.repo_mgr.remotes if r['url'].startswith(text)]
        return []

    def complete_use(self, text, *_): return [m for m in self.modules if m.startswith(text)]
    def complete_gen(self, text, *_): return [m for m in self.modules if m.startswith(text)]
    def complete_kill(self, text, *_): return [str(j.jid) for j in self.jobs.all() if str(j.jid).startswith(text)]
    def complete_info(self, text, *_):
        known = list(self.modules.keys()) + list(self._untrusted.keys())
        return [m for m in known if m.startswith(text)]
    def complete_set(self, text, *_): return [k for k in (self.current_options or {}) if k.startswith(text)]
    def complete_unset(self, text, *_): return self.complete_set(text, *_)
    def complete_help(self, text, *_):
        cmds = ["help","banner","clear","reload","exit","modules","ls","search","info","use","back",
                "options","set","unset","run","sessions","deps","new_module","add_module","install_local","remove",
                "setg","globals","status","repo",
                "trust","untrust","trusted","verify"]
        return [x for x in cmds if x.startswith(text)]

    def completedefault(self, text, line, begidx, endidx):
        if self._subshell_active and callable(self._subshell_completer):
            try: return self._subshell_completer(text, line, begidx, endidx)
            except Exception: return []
        return []


def main():
    if "--no-banner" not in sys.argv: print_banner(animate=True)
    else: print(f"  {C.PINK}Eidolon{C.RESET} {CODENAME} v{__version__}\n")

    shell = Eidolon()
    try: shell.cmdloop()
    except KeyboardInterrupt: print(); shell.do_exit("")
    except EOFError: shell.do_exit("")


if __name__ == "__main__":
    main()