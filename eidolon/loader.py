import os
import importlib.util
from eidolon.utils import spectral, err, warn

MODULE_TYPE_AUXILIARY = "auxiliary"
MODULE_TYPE_GENERIC   = "generic"
MODULE_TYPE_EXPLOIT   = "exploit"

VALID_MODULE_TYPES = {MODULE_TYPE_AUXILIARY, MODULE_TYPE_GENERIC, MODULE_TYPE_EXPLOIT}
_MODULE_TYPE_ALIASES = {
    "aux": MODULE_TYPE_AUXILIARY, "auxiliary": MODULE_TYPE_AUXILIARY,
    "generic": MODULE_TYPE_GENERIC, "public": MODULE_TYPE_GENERIC,
    "exploit": MODULE_TYPE_EXPLOIT, "exp": MODULE_TYPE_EXPLOIT,
}

def _module_type(mod) -> str:
    raw = str(getattr(mod, "MODULE_TYPE", "") or "").strip().lower()
    return _MODULE_TYPE_ALIASES.get(raw, MODULE_TYPE_GENERIC)

def _cleanup_legacy_scaffolds(modules_dir):
    legacy = {
        "_template.py": ('NAME        = "My Module"', 'CATEGORY    = "misc"'),
        "example_sysinfo.py": ('NAME        = "System Info"', 'CATEGORY    = "recon"'),
    }
    for fn, markers in legacy.items():
        path = os.path.join(modules_dir, fn)
        if not os.path.exists(path): continue
        try:
            with open(path, "r", encoding="utf-8") as f: content = f.read()
        except OSError: continue
        if all(m in content for m in markers):
            try:
                os.remove(path)
                spectral(f"removed legacy scaffold: {fn}")
            except OSError as e:
                warn(f"cannot remove legacy {fn}: {e}")

def iter_module_files(modules_dir):
    try:
        for root, dirs, files in os.walk(modules_dir):
            dirs[:] = sorted(d for d in dirs if not d.startswith(("_", "@")))
            for fn in sorted(files):
                if not fn.endswith(".py") or fn.startswith(("_", "@")): continue
                path = os.path.join(root, fn)
                rel = os.path.relpath(path, modules_dir).replace(os.sep, "/")
                yield path, rel
    except OSError as e:
        err(f"cannot walk modules dir: {e}")

def load_module_from_path(path, globals_dict, shell_instance):
    try:
        safe_name = os.path.basename(path).replace("/", "__").replace(".py", "")
        spec = importlib.util.spec_from_file_location(f"eidolon_mod_{safe_name}", path)
        if spec is None or spec.loader is None: raise ImportError("cannot build spec")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        mod.__eidolon_path__ = path
        mod.EIDOLON_GLOBALS = globals_dict
        mod.EIDOLON_SHELL = shell_instance
        return mod, None
    except Exception as e:
        return None, str(e)