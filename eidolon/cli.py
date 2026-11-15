import os
import sys
import cmd
import copy
import time
import shlex
import traceback
import shutil
import glob
from pathlib import Path

from eidolon.colors import C, rl_prompt_safe, c
from eidolon.utils import (
    ok, err, info, warn, spectral, hr, print_banner, print_splash, print_table,
    _uptime_str, _fmt_duration, _cvss_severity, _cvss_color, _module_vulns, _module_cvss
)
from eidolon.loader import (
    iter_module_files, load_module_from_path, _module_type, _cleanup_legacy_scaffolds,
    MODULE_TYPE_EXPLOIT, MODULE_TYPE_AUXILIARY, MODULE_TYPE_GENERIC
)
from eidolon.database import EidolonDB

WORKSPACE_DIR = os.path.join(os.path.expanduser("~"), ".eidolon")
MODULES_DIR = os.path.join(WORKSPACE_DIR, "modules")
DB_PATH = os.path.join(WORKSPACE_DIR, "eidolon.db")

_TYPE_COLOR = {
    MODULE_TYPE_AUXILIARY: "blue",
    MODULE_TYPE_GENERIC:   "gray",
    MODULE_TYPE_EXPLOIT:   "red",
}

def _type_label(mod) -> str:
    t = _module_type(mod)
    return c(t, _TYPE_COLOR.get(t, "white"))

class Eidolon(cmd.Cmd):
    intro = ""
    use_rawinput = True

    def __init__(self):
        super().__init__()
        os.makedirs(MODULES_DIR, exist_ok=True)
        self.db = EidolonDB(DB_PATH)
        self.globals = self.db.get_globals()
        self.modules = {}
        self._module_mtimes = {}
        self.current = None
        self.current_name = None
        self.current_options = None
        
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
        # BUGFIX: Tell readline to ONLY break words on space, tab, and newline.
        # Otherwise, it breaks on '/' and messes up directory tab completion.
        try:
            import readline
            readline.set_completer_delims(' \t\n')
        except ImportError:
            pass

        print_splash()
        _cleanup_legacy_scaffolds(MODULES_DIR)
        self.load_modules()
        print()
        spectral(f"welcome back, {C.BOLD}{self.operator_name}{C.RESET}")
        spectral(f"workspace : {C.CYAN}{WORKSPACE_DIR}{C.RESET}")
        spectral(f"modules   : {C.GREEN}{len(self.modules)}{C.RESET} loaded")
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

    def load_modules(self):
        self.modules = {}
        self._module_mtimes = {}
        t0 = time.time()
        failed = 0
        seen_names = set()
        
        for path, rel in iter_module_files(MODULES_DIR):
            name = rel[:-3]
            if name in seen_names:
                warn(f"duplicate module '{name}' — skipped")
                failed += 1
                continue
            seen_names.add(name)
            
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
        spectral(f"{len(self.modules)} module(s) loaded in {dt:.1f} ms{tail}")

    def _resolve(self, name):
        name = name.strip()
        if name in self.modules: return name
        matches = [k for k in self.modules if name in k]
        return matches[0] if len(matches) == 1 else None

    def _auto_session_target(self):
        opts = self.current_options or {}
        for key in ("target", "rhost", "rhosts", "host", "hostname", "url", "uri"):
            if key in opts:
                v = opts[key].get("value")
                if v not in (None, "", False): return str(v)
        for k, v in opts.items():
            val = v.get("value")
            if val not in (None, "", False): return str(val)
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

    # --- CORE COMMANDS ---
    
    def do_add_module(self, arg):
        """add_module <path> — Install a new module from a file into the workspace"""
        path = arg.strip()
        if not path:
            err("usage: add_module <path_to_python_file>")
            return
            
        # Strip surrounding quotes if user provided them (e.g. for paths with spaces)
        if (path.startswith('"') and path.endswith('"')) or (path.startswith("'") and path.endswith("'")):
            path = path[1:-1]
            
        src_path = Path(os.path.expanduser(path))
        if not src_path.is_absolute():
            src_path = Path.cwd() / src_path
            
        if not src_path.exists() or not src_path.is_file():
            err(f"file not found: {src_path}")
            return
            
        if not str(src_path).endswith(".py"):
            err("only .py files are allowed.")
            return

        dest_path = Path(MODULES_DIR) / src_path.name
        try:
            shutil.copy2(src_path, dest_path)
            ok(f"module copied to workspace: {dest_path.name}")
            self.load_modules()
        except Exception as e:
            err(f"failed to copy: {e}")

    def do_help(self, arg):
        """help [cmd] — show help"""
        arg = arg.strip()
        if arg:
            meth = getattr(self, f"do_{arg}", None)
            if not meth: return err(f"no such command: {arg}")
            print(f"\n  {C.PINK}{arg}{C.RESET}  —  {(meth.__doc__ or '').strip().splitlines()[0]}\n")
            return

        print(f"\n{C.PURPLE}╭─────────────────────────────────────────╮{C.RESET}")
        print(f"{C.PURPLE}│{C.RESET}  {C.PINK}EIDOLON{C.RESET} {C.GRAY}·{C.RESET} {C.CYAN}SPECTRAL CORE{C.RESET} {C.GRAY}·{C.RESET} reference")
        print(f"{C.PURPLE}╰─────────────────────────────────────────╯{C.RESET}")
        print(f"  {C.CYAN}help{C.RESET} / {C.CYAN}clear{C.RESET} / {C.CYAN}banner{C.RESET} / {C.CYAN}reload{C.RESET} / {C.CYAN}exit{C.RESET}")
        print(f"  {C.CYAN}modules{C.RESET} / {C.CYAN}search{C.RESET} <kw> / {C.CYAN}info{C.RESET} <name>")
        print(f"  {C.CYAN}use{C.RESET} <name> / {C.CYAN}back{C.RESET} / {C.CYAN}options{C.RESET} / {C.CYAN}set{C.RESET} <k> <v> / {C.CYAN}run{C.RESET}")
        print(f"  {C.CYAN}sessions{C.RESET} / {C.CYAN}add_module{C.RESET} <path> (install new tool)")
        print(f"  {C.CYAN}setg{C.RESET} <k> <v> / {C.CYAN}globals{C.RESET}\n")

    def do_banner(self, arg): print_banner(animate=True)
    def do_clear(self, arg): os.system("cls" if os.name == "nt" else "clear")
    
    def do_reload(self, arg):
        """reload — rescan workspace modules"""
        if self._subshell_active: self.exit_subshell()
        spectral("reloading module arsenal ...")
        self.current = self.current_name = self.current_options = None
        self.load_modules()
        ok("arsenal reloaded")

    def do_status(self, arg):
        """status — show operator status"""
        sessions = self.db.get_sessions()
        active = sum(1 for s in sessions if s["status"] == "active")
        print(f"\n  {C.PURPLE}╭─ OPERATOR STATUS ──────────────────╮{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  name      : {C.BOLD}{self.operator_name}{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  team      : {C.CYAN}{self.operator_team}{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  uptime    : {_uptime_str(self.session_t0)}")
        print(f"  {C.PURPLE}│{C.RESET}  workspace : {C.GREEN}{WORKSPACE_DIR}{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET}  sessions  : {C.GREEN}{active}{C.RESET} active")
        print(f"  {C.PURPLE}╰────────────────────────────────────╯\n")

    def do_whoami(self, arg): self.do_status("")

    def do_operator(self, arg):
        parts = arg.strip().split(maxsplit=1)
        if not parts: return print(f"operator: {self.operator_name} @ {self.operator_team}")
        field, value = parts[0].lower(), (parts[1].strip() if len(parts) > 1 else "")
        if field == "name" and value: self.operator_name = value; ok("name updated")
        elif field == "team" and value: self.operator_team = value; ok("team updated")
        else: err("usage: operator name|team <val>")

    def do_exit(self, arg):
        """exit / quit — leave tool"""
        if self._subshell_active:
            self.exit_subshell(); ok("returned to Eidolon"); return False
        print(f"\n  {C.PURPLE}╰─{C.RESET} {C.CYAN}eidolon out.{C.RESET}  {C.GRAY}uptime: {_uptime_str(self.session_t0)}{C.RESET}\n")
        return True

    do_quit = do_exit
    def do_EOF(self, arg): print(); return self.do_exit(arg)

    def do_modules(self, arg):
        if not self.modules: return warn("no modules loaded.")
        rows = []
        for i, (name, m) in enumerate(sorted(self.modules.items()), 1):
            rows.append([f"{C.PURPLE}{i:02d}{C.RESET}", f"{C.CYAN}{name}{C.RESET}", _type_label(m), getattr(m, "CATEGORY", "-"), str(getattr(m, "DESCRIPTION", "-"))[:36]])
        print_table(["#", "Arsenal", "Type", "Category", "Description"], rows, title=f"EIDOLON ARSENAL ({len(self.modules)})")
    do_list = do_ls = do_arsenal = do_modules

    def do_search(self, arg):
        kw = arg.strip().lower()
        if not kw: return err("usage: search <keyword>")
        hits = [name for name, m in self.modules.items() if kw in (name + str(getattr(m, "DESCRIPTION", ""))).lower()]
        if not hits: return warn("no matches.")
        for h in sorted(hits): print(f"     {C.PINK}▸{C.RESET} {h}")

    def do_info(self, arg):
        name = self._resolve(arg)
        if not name: return err(f"not found: '{arg.strip()}'")
        m = self.modules[name]
        print(f"\n  {C.PURPLE}╭─ MODULE INTEL ─────────────────────╮{C.RESET}")
        print(f"  {C.PURPLE}│{C.RESET} name: {c(name, C.WHITE)}")
        print(f"  {C.PURPLE}│{C.RESET} type: {_type_label(m)} | cat: {getattr(m,'CATEGORY','-')}")
        print(f"  {C.PURPLE}│{C.RESET} desc: {getattr(m,'DESCRIPTION','-')}")
        print(f"  {C.PURPLE}│{C.RESET} file: {getattr(m,'__eidolon_path__','?')}")
        print(f"  {C.PURPLE}╰────────────────────────────────────╯")
        opts = getattr(m, "OPTIONS", {})
        if opts:
            rows = [[k, str(v.get("value", "")), "yes" if v.get("required") else "no", v.get("desc", "")] for k, v in opts.items()]
            print_table(["Name", "Default", "Req", "Desc"], rows, title="OPTIONS")
        print()

    def do_use(self, arg):
        name = self._resolve(arg)
        if not name: return err(f"module '{arg.strip()}' not found.")
        mod = self.modules[name]
        self.current = mod
        self.current_name = name
        self.current_options = copy.deepcopy(getattr(mod, "OPTIONS", {}))
        ok(f"selected: {c(name, C.PINK)}")
        self.do_options("")

    def do_back(self, arg):
        if self._subshell_active: self.exit_subshell()
        if not self.current: return warn("no module selected.")
        spectral(f"left {self.current_name}")
        self.current = self.current_name = self.current_options = None
    do_vanish = do_back

    def do_options(self, arg):
        if not self.current: return err("no module selected.")
        opts = self.current_options or {}
        if not opts: return info("no options.")
        rows = [[k, str(v.get("value", "")), "yes" if v.get("required") else "no", v.get("desc", "")] for k, v in opts.items()]
        print_table(["Name", "Value", "Req", "Desc"], rows, title=f"OPTIONS · {self.current_name}")

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
        ok(f"{C.CYAN}{key}{C.RESET} → {self.current_options[key]['value']!r}")

    def do_unset(self, arg):
        key = arg.strip()
        if not self.current or key not in (self.current_options or {}): return err(f"unknown: {key}")
        default = getattr(self.current, "OPTIONS", {}).get(key, {}).get("value", "")
        self.current_options[key]["value"] = copy.deepcopy(default)
        spectral(f"{key} reset to default")

    def do_run(self, arg):
        if not self.current: return err("no module selected.")
        missing = [k for k, v in (self.current_options or {}).items() if v.get("required") and v.get("value") in (None, "", [], {})]
        if missing: return err(f"missing required: {', '.join(missing)}")

        values = {k: v.get("value") for k, v in self.current_options.items()}
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

    do_exploit = do_run
    do_exec    = do_run
    do_haunt   = do_run

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

    # TAB COMPLETION
    def complete_use(self, text, *_): return [m for m in self.modules if m.startswith(text)]
    def complete_info(self, text, *_): return self.complete_use(text, *_)
    def complete_set(self, text, *_): return [k for k in (self.current_options or {}) if k.startswith(text)]
    def complete_unset(self, text, *_): return self.complete_set(text, *_)
    def complete_operator(self, text, *_): return [x for x in ["name", "team"] if x.startswith(text)]
    
    def complete_add_module(self, text, line, begidx, endidx):
        # Remove quotes to safely handle paths
        clean_text = text.strip("'\"")
        
        # Expand ~ for the glob search
        expanded_text = os.path.expanduser(clean_text)
        
        # Find matches using glob
        matches = glob.glob(expanded_text + '*')
        
        results = []
        for match in matches:
            is_dir = os.path.isdir(match)
            
            # Only list directories or .py files
            if is_dir or match.endswith('.py'):
                display_match = match
                
                # Convert absolute home path back to ~ if it was used
                if clean_text.startswith('~'):
                    home = os.path.expanduser('~')
                    if display_match.startswith(home):
                        display_match = '~' + display_match[len(home):]
                        
                # Append slash for directories
                if is_dir and not display_match.endswith('/'):
                    display_match += '/'
                    
                # Re-apply quotes if originally present
                if text.startswith("'") and not display_match.startswith("'"):
                    display_match = "'" + display_match + "'"
                elif text.startswith('"') and not display_match.startswith('"'):
                    display_match = '"' + display_match + '"'
                    
                results.append(display_match)
                
        return results

    def complete_help(self, text, *_):
        return [x for x in ["help","banner","clear","reload","exit","modules","search","info","use","back","options","set","unset","run","sessions","add_module","setg","globals","status","whoami","operator"] if x.startswith(text)]

    def completedefault(self, text, line, begidx, endidx):
        if self._subshell_active and callable(self._subshell_completer):
            try: return self._subshell_completer(text, line, begidx, endidx)
            except Exception: return []
        return []

def main():
    if "--no-banner" not in sys.argv: print_banner(animate=True)
    else: print(f"  {C.PINK}Eidolon{C.RESET} v3.1.1\n")

    shell = Eidolon()
    try: shell.cmdloop()
    except KeyboardInterrupt: print(); shell.do_exit("")
    except EOFError: shell.do_exit("")

if __name__ == "__main__":
    main()