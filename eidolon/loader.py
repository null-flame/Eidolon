import os
import json
import time
import importlib.util
import threading
from eidolon.utils import spectral, err, warn, sha256_of_path, sha256_of_dir

MODULE_TYPE_AUXILIARY = "auxiliary"
MODULE_TYPE_GENERIC   = "generic"
MODULE_TYPE_EXPLOIT   = "exploit"
MODULE_TYPE_PAYLOAD   = "payload"

VALID_MODULE_TYPES = {MODULE_TYPE_AUXILIARY, MODULE_TYPE_GENERIC, MODULE_TYPE_EXPLOIT,
                      MODULE_TYPE_PAYLOAD}
_MODULE_TYPE_ALIASES = {
    "aux": MODULE_TYPE_AUXILIARY, "auxiliary": MODULE_TYPE_AUXILIARY,
    "generic": MODULE_TYPE_GENERIC, "public": MODULE_TYPE_GENERIC,
    "exploit": MODULE_TYPE_EXPLOIT, "exp": MODULE_TYPE_EXPLOIT,
    "payload": MODULE_TYPE_PAYLOAD, "c2": MODULE_TYPE_PAYLOAD,
}

WORKSPACE_DIR = os.path.join(os.path.expanduser("~"), ".eidolon")
MODULES_DIR   = os.path.join(WORKSPACE_DIR, "modules")
TRUST_FILE    = os.path.join(WORKSPACE_DIR, "trust.json")


def _module_type(mod) -> str:
    raw = str(getattr(mod, "MODULE_TYPE", "") or "").strip().lower()
    return _MODULE_TYPE_ALIASES.get(raw, MODULE_TYPE_GENERIC)


# ═══════════════════════════════════════════════════════════════
#  TRUST MANAGER — TOFU (Trust On First Use)
# ═══════════════════════════════════════════════════════════════

class TrustManager:
    """
    TOFU trust system.

    - Every installed module starts UNTRUSTED.
    - User must explicitly `trust <module>` to record its hash and enable loading.
    - On every load, current file hash is compared against the recorded hash.
    - If file changed → marked MODIFIED, never loaded, user must re-trust.
    - All hashes stored in ~/.eidolon/trust.json (0600).
    """

    def __init__(self, modules_dir: str = None, trust_file: str = None):
        self.modules_dir = modules_dir or MODULES_DIR
        self.trust_file  = trust_file  or TRUST_FILE
        os.makedirs(os.path.dirname(self.trust_file), exist_ok=True)
        self._lock = threading.Lock()
        self.data = self._load()

    # ── persistence ────────────────────────────────────────
    def _load(self):
        if not os.path.exists(self.trust_file):
            return {"version": 1, "modules": {}}
        try:
            with open(self.trust_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict) or "modules" not in data:
                raise ValueError("invalid trust.json structure")
            if not isinstance(data["modules"], dict):
                raise ValueError("'modules' must be a dict")
            return data
        except Exception:
            warn("trust.json corrupted, starting fresh")
            return {"version": 1, "modules": {}}

    def _save(self):
        tmp = self.trust_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, sort_keys=True)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.trust_file)

    # ── lookup ─────────────────────────────────────────────
    def _file_for(self, module_key: str) -> str:
        """Absolute path to the .py file for a module key."""
        return os.path.join(self.modules_dir, module_key + ".py")

    def _hash_for(self, module_key: str, file_path: str) -> str:
        """Compute hash of a module file or directory."""
        if os.path.isdir(file_path):
            return sha256_of_dir(file_path)
        return sha256_of_path(file_path)

    def get_entry(self, module_key: str):
        return self.data["modules"].get(module_key)

    def is_trusted(self, module_key: str, file_path: str):
        """
        Returns (ok: bool, status: str).
        status: "ok" | "untrusted" | "modified" | "missing" | "unreadable"
        """
        if not os.path.exists(file_path):
            return False, "missing"
        entry = self.data["modules"].get(module_key)
        if not entry:
            return False, "untrusted"
        if not entry.get("trusted", False):
            return False, "untrusted"
        try:
            current = self._hash_for(module_key, file_path)
        except OSError:
            return False, "unreadable"
        stored = entry.get("sha256", "")
        if not stored or current != stored:
            return False, "modified"
        return True, "ok"

    # ── mutation ───────────────────────────────────────────
    def register_untrusted(self, module_key: str, file_path: str, **meta):
        """Called after install / upgrade. Records hash, marks untrusted."""
        with self._lock:
            try:
                h = self._hash_for(module_key, file_path)
            except OSError:
                return
            self.data["modules"][module_key] = {
                "sha256":        h,
                "trusted":       False,
                "registered_at": time.time(),
                **{k: v for k, v in meta.items() if v is not None},
            }
            self._save()

    def trust(self, module_key: str, file_path: str, **meta) -> str:
        """Explicit trust: records current hash and marks trusted. Returns hash."""
        with self._lock:
            h = self._hash_for(module_key, file_path)
            entry = dict(self.data["modules"].get(module_key, {}))
            entry.update({
                "sha256":     h,
                "trusted":    True,
                "trusted_at": time.time(),
            })
            entry.setdefault("registered_at", time.time())
            for k, v in meta.items():
                if v is not None:
                    entry[k] = v
            self.data["modules"][module_key] = entry
            self._save()
            return h

    def untrust(self, module_key: str) -> bool:
        with self._lock:
            if module_key in self.data["modules"]:
                del self.data["modules"][module_key]
                self._save()
                return True
            return False

    # ── bulk ───────────────────────────────────────────────
    def list_all(self) -> dict:
        return dict(self.data["modules"])

    def verify_all(self) -> dict:
        """Returns {module_key: status} for every registered module."""
        results = {}
        for key, entry in self.data["modules"].items():
            fp = self._file_for(key)
            if not os.path.exists(fp):
                results[key] = "missing"
                continue
            if not entry.get("trusted", False):
                results[key] = "untrusted"
                continue
            try:
                cur = self._hash_for(key, fp)
            except OSError:
                results[key] = "unreadable"
                continue
            results[key] = "ok" if cur == entry.get("sha256") else "modified"
        return results

    def purge_orphans(self) -> list:
        """Remove trust entries whose files no longer exist."""
        removed = []
        with self._lock:
            for key in list(self.data["modules"].keys()):
                if not os.path.exists(self._file_for(key)):
                    del self.data["modules"][key]
                    removed.append(key)
            if removed:
                self._save()
        return removed


# ═══════════════════════════════════════════════════════════════
#  MODULE LOADING (unchanged)
# ═══════════════════════════════════════════════════════════════

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
            dirs[:] = sorted(d for d in dirs if not d.startswith(("_", "@", "src", "lib", ".")))
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