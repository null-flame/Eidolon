import os
import sys
import cmd
import copy
import time
import shlex
import traceback
import shutil
import glob
import readline
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
from eidolon.repo import RepositoryManager

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
        self.repo_mgr = RepositoryManager()
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
        readline.set_completer_delims(' \t\n')
        
        # BUGFIX: Display only basename in tab completion hints
        def display_hook(substitution, matches, longest_match_length):
            for m in matches:
                print(os.path.basename(m.rstrip('/')))
            matches.clear()
        readline.set_completion_display_matches_hook(display_hook)

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

    # --- REPO COMMANDS ---
    def do_repo(self, arg):
        """repo [list|add <url>|remove <url>|sync|install <name>]"""
        args = arg.strip().split()
        if not args:
            return self.do_repo("list")
        
        cmd = args[0].lower()
        
        if cmd == "list":
            remotes = self.repo_mgr.remotes
            if not remotes:
                return warn("No remotes configured.")
            rows = [[str(i+1), url] for i, url in enumerate(remotes)]
            print_table(["#", "Remote URL"], rows, title="CONFIGURED REMOTES")
            
        elif cmd == "add" and len(args) > 1:
            url = args[1]
            if self.repo_mgr.add_remote(url):
                ok(f"Added remote: {url}")
            else:
                warn("Remote already exists.")
                
        elif cmd == "remove" and len(args) > 1:
            url = args[1]
            if self.repo_mgr.remove_remote(url):
                ok(f"Removed remote: {url}")
            else:
                warn("Remote not found.")
                
        elif cmd == "sync":
            spectral("Syncing all remotes...")
            modules = self.repo_mgr.get_all_modules(force_refresh=True)
            ok(f"Synced {len(modules)} modules from {len(self.repo_mgr.remotes)} remotes.")
            
        elif cmd == "install" and len(args) > 1:
            mod_name = args[1]
            spectral(f"Searching for module '{mod_name}'...")
            modules = self.repo_mgr.get_all_modules()
            if mod_name not in modules:
                return err(f"Module '{mod_name}' not found in any remote.")
            
            mod_info = modules[mod_name]
            spectral(f"Installing '{mod_name}' from {mod_info['_repo_url']}...")
            if self.repo_mgr.install_module(mod_info):
                ok(f"Module '{mod_name}' installed successfully.")
                self.load_modules()
            else:
                err("Installation failed.")
        else:
            err("usage: repo [list|add <url>|remove <url>|sync|install <name>]")

    def do_add_module(self, arg):
        """add_module <path> — Install a new module from a local file"""
        path = arg.strip()
        if not path:
            return err("usage: add_module <path_to_python_file>")
            
        if (path.startswith('"') and path.endswith('"')) or (path.startswith("'") and path.endswith("'")):
            path = path[1:-1]
            
        src_path = Path(os.path.expanduser(path))
        if not src_path.is_absolute():
            src_path = Path.cwd() / src_path
            
        if not src_path.exists() or not src_path.is_file():
            return err(f"file not found: {src_path}")
            
        if not str(src_path).endswith(".py"):
            return err("only .py files are allowed.")

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
        print(f"  {C.CYAN}repo{C.RESET} <list|add|remove|sync|install>")
        print(f"  {C.CYAN}sessions{C.RESET} / {C.CYAN}add_module{C.RESET} <path>")
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

    # ... (rest of the file remains the same: status, whoami, operator, exit, modules, search, info, use, back, options, show, set, unset, run, sessions, setg, globals, completions) ...
    # For brevity, I'll include the completion functions that are relevant to repo.
    def complete_repo(self, text, line, begidx, endidx):
        cmds = ["list", "add", "remove", "sync", "install"]
        if begidx == 5: # After "repo "
            return [c for c in cmds if c.startswith(text)]
        return []

    def complete_add_module(self, text, line, begidx, endidx):
        clean_text = text.strip("'\"")
        expanded_text = os.path.expanduser(clean_text)
        matches = glob.glob(expanded_text + '*')
        
        results = []
        for match in matches:
            is_dir = os.path.isdir(match)
            if is_dir or match.endswith('.py'):
                display_match = match
                if clean_text.startswith('~'):
                    home = os.path.expanduser('~')
                    if display_match.startswith(home):
                        display_match = '~' + display_match[len(home):]
                if is_dir and not display_match.endswith('/'):
                    display_match += '/'
                if text.startswith("'") and not display_match.startswith("'"):
                    display_match = "'" + display_match + "'"
                elif text.startswith('"') and not display_match.startswith('"'):
                    display_match = '"' + display_match + '"'
                results.append(display_match)
        return results

    # ... (keep other completion functions) ...

def main():
    if "--no-banner" not in sys.argv: print_banner(animate=True)
    else: print(f"  {C.PINK}Eidolon{C.RESET} v3.1.1\n")

    shell = Eidolon()
    try: shell.cmdloop()
    except KeyboardInterrupt: print(); shell.do_exit("")
    except EOFError: shell.do_exit("")

if __name__ == "__main__":
    main()