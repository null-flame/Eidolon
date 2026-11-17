import os
import json
import hashlib
import tarfile
import shutil
import time
import subprocess
import urllib.request

import zstandard as zstd

from eidolon import __version__
from eidolon.utils import spectral, err, ok, warn, version_tuple, sha256_of_path

WORKSPACE_DIR = os.path.join(os.path.expanduser("~"), ".eidolon")
REPOS_FILE    = os.path.join(WORKSPACE_DIR, "remotes.json")
CACHE_DIR     = os.path.join(WORKSPACE_DIR, "cache")
MODULES_DIR   = os.path.join(WORKSPACE_DIR, "modules")

DEFAULT_REPO = "https://raw.githubusercontent.com/null-flame/Eidolon/refs/heads/main/modules.json"
USER_AGENT   = f"Eidolon/{__version__} (+https://github.com/null-flame/Eidolon)"

CACHE_TTL          = 3600
DOWNLOAD_TIMEOUT   = 60
METADATA_TIMEOUT   = 15

# anti-DoS download caps
MAX_JSON_SIZE      = 5 * 1024 * 1024    # 5 MB  — index / metadata payloads
MAX_ARCHIVE_SIZE   = 50 * 1024 * 1024   # 50 MB — module archives

# ─────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────

def _cache_path(url: str) -> str:
    digest   = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
    basename = os.path.basename(url.split("?", 1)[0]) or "index.json"
    return os.path.join(CACHE_DIR, f"{digest}_{basename}")


def _safe_extract_tar(tar: tarfile.TarFile, target: str):
    abs_target = os.path.abspath(target)
    os.makedirs(abs_target, exist_ok=True)
    try:
        tar.extractall(path=abs_target, filter="data")
        return
    except TypeError:
        pass
    for member in tar.getmembers():
        member_path = os.path.abspath(os.path.join(abs_target, member.name))
        if member_path != abs_target and not member_path.startswith(abs_target + os.sep):
            raise ValueError(f"unsafe path in archive: {member.name!r}")
        if member.issym() or member.islnk():
            link_path = os.path.abspath(
                os.path.join(abs_target, os.path.dirname(member.name), member.linkname)
            )
            if link_path != abs_target and not link_path.startswith(abs_target + os.sep):
                raise ValueError(f"unsafe link in archive: {member.name!r} -> {member.linkname!r}")
    tar.extractall(path=abs_target)


def _open_url(url: str, timeout: float):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout)


def _safe_download(url: str, dest_path: str, max_size: int, timeout: float) -> bool:
    """Stream a remote file to dest_path, refusing payloads larger than max_size."""
    try:
        with _open_url(url, timeout=timeout) as r, open(dest_path, "wb") as out:
            header_len = r.headers.get("Content-Length")
            if header_len and header_len.isdigit() and int(header_len) > max_size:
                err(f"download aborted: exceeds size limit ({max_size // (1024 * 1024)} MB): {url}")
                return False
            downloaded = 0
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                downloaded += len(chunk)
                if downloaded > max_size:
                    err(f"download aborted: exceeded size limit mid-stream ({max_size // (1024 * 1024)} MB): {url}")
                    return False
                out.write(chunk)
        return True
    except Exception as e:
        err(f"download failed: {url} ({e})")
        return False


# ─────────────────────────────────────────────────────────────
# manager
# ─────────────────────────────────────────────────────────────

class RepositoryManager:
    def __init__(self):
        os.makedirs(CACHE_DIR, exist_ok=True)
        os.makedirs(MODULES_DIR, exist_ok=True)
        self.remotes = self._load_remotes()

    # ── persistence ─────────────────────────────────────────
    def _default_remotes(self):
        return [{"url": DEFAULT_REPO, "enabled": True, "priority": 10}]

    def _load_remotes(self):
        if not os.path.exists(REPOS_FILE):
            data = self._default_remotes()
            self._save_remotes(data)
            return data
        try:
            with open(REPOS_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if not isinstance(raw, list):
                raise ValueError("remotes.json must contain a list")
            if raw and isinstance(raw[0], str):
                raw = [{"url": u, "enabled": True, "priority": 10} for u in raw]
            clean = []
            for entry in raw:
                if not isinstance(entry, dict) or "url" not in entry:
                    continue
                clean.append({
                    "url":      entry["url"],
                    "enabled":  bool(entry.get("enabled", True)),
                    "priority": int(entry.get("priority", 10)),
                })
            if not clean:
                raise ValueError("no valid remotes in file")
            return clean
        except Exception as e:
            warn(f"remotes.json corrupted, resetting: {e}")
            data = self._default_remotes()
            try:
                self._save_remotes(data)
            except OSError:
                pass
            return data

    def _save_remotes(self, remotes):
        tmp = REPOS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(remotes, f, indent=2)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, REPOS_FILE)

    # ── mutation ────────────────────────────────────────────
    def add_remote(self, url: str, validate: bool = True):
        if any(r["url"] == url for r in self.remotes):
            return False, "remote already exists"
        if validate:
            valid, reason = self._validate_remote(url)
            if not valid:
                return False, reason
        self.remotes.append({"url": url, "enabled": True, "priority": 10})
        self._save_remotes(self.remotes)
        return True, ""

    def _validate_remote(self, url: str):
        if not url.lower().startswith("https://"):
            return False, "URL must use HTTPS"
        try:
            with _open_url(url, timeout=METADATA_TIMEOUT) as r:
                raw = r.read(MAX_JSON_SIZE + 1)
            if len(raw) > MAX_JSON_SIZE:
                return False, "index exceeds size limit"
            payload = json.loads(raw.decode("utf-8"))
        except Exception as e:
            return False, f"unreachable or invalid JSON: {e}"
        if not isinstance(payload, dict) or "modules" not in payload:
            return False, "missing 'modules' key"
        if not isinstance(payload["modules"], list):
            return False, "'modules' must be a list"
        return True, ""

    def remove_remote(self, url: str) -> bool:
        before = len(self.remotes)
        self.remotes = [r for r in self.remotes if r["url"] != url]
        if len(self.remotes) < before:
            self._save_remotes(self.remotes)
            return True
        return False

    def toggle_remote(self, url: str, enable: bool = True) -> bool:
        for r in self.remotes:
            if r["url"] == url:
                r["enabled"] = enable
                self._save_remotes(self.remotes)
                return True
        return False

    def set_priority(self, url: str, priority: int) -> bool:
        for r in self.remotes:
            if r["url"] == url:
                r["priority"] = int(priority)
                self._save_remotes(self.remotes)
                return True
        return False

    # ── fetch / cache ───────────────────────────────────────
    def fetch_repo_json(self, url: str, force_refresh: bool = False):
        cache_file = _cache_path(url)
        if not force_refresh and os.path.exists(cache_file):
            try:
                if time.time() - os.path.getmtime(cache_file) < CACHE_TTL:
                    with open(cache_file, "r", encoding="utf-8") as f:
                        return json.load(f)
            except (OSError, json.JSONDecodeError):
                pass
        try:
            with _open_url(url, timeout=METADATA_TIMEOUT) as r:
                raw = r.read(MAX_JSON_SIZE + 1)
            if len(raw) > MAX_JSON_SIZE:
                raise ValueError("index exceeds size limit")
            data = json.loads(raw.decode("utf-8"))
            tmp = cache_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, cache_file)
            return data
        except Exception:
            if os.path.exists(cache_file):
                try:
                    with open(cache_file, "r", encoding="utf-8") as f:
                        return json.load(f)
                except (OSError, json.JSONDecodeError):
                    pass
            return None

    def sync_json(self, force_refresh: bool = True) -> int:
        count = 0
        for r in self.remotes:
            if not r.get("enabled", True):
                continue
            if self.fetch_repo_json(r["url"], force_refresh=force_refresh) is not None:
                count += 1
            else:
                warn(f"Failed to sync {r['url']}")
        return count

    # ── module discovery ────────────────────────────────────
    def get_all_modules(self, force_refresh: bool = False) -> dict:
        merged = {}
        remotes = sorted(
            (r for r in self.remotes if r.get("enabled", True)),
            key=lambda x: x.get("priority", 10),
            reverse=True,
        )
        for r in remotes:
            data = self.fetch_repo_json(r["url"], force_refresh)
            if not data or "modules" not in data:
                continue
            for mod in data["modules"]:
                if not isinstance(mod, dict) or "name" not in mod:
                    continue
                mod["_repo_url"] = r["url"]
                if mod["name"] not in merged:
                    merged[mod["name"]] = mod
        return merged

    def find_by_local_name(self, local_name: str, all_modules: dict = None):
        if all_modules is None:
            all_modules = self.get_all_modules()
        base = os.path.basename(local_name.replace("\\", "/"))
        candidates = [base]
        if "_" in base:
            candidates.append(base.replace("_", "-"))
        if "-" in base:
            candidates.append(base.replace("-", "_"))
        for cand in candidates:
            if cand in all_modules:
                return cand, all_modules[cand]
        return None, None

    # ── install ─────────────────────────────────────────────
    def install_module(self, module_info: dict, force: bool = False, trust_mgr=None):
        """Install. Returns (ok: bool, reason: str). If trust_mgr given, register untrusted."""
        name     = module_info.get("name")
        path     = module_info.get("path") or name
        mod_type = module_info.get("type", "tar")
        url      = module_info.get("url")
        sha      = module_info.get("sha256")

        if not name:
            return False, "module entry missing 'name'"
        if not url:
            return False, "module entry missing 'url'"

        target_dir = os.path.join(MODULES_DIR, path)

        # path traversal guard: resolved target must stay inside MODULES_DIR
        real_modules = os.path.realpath(MODULES_DIR)
        real_target  = os.path.realpath(target_dir)
        if real_target != real_modules and not real_target.startswith(real_modules + os.sep):
            return False, f"unsafe module path (path traversal?): {path!r}"

        if not force and os.path.isdir(target_dir) and any(
            not e.startswith(".") for e in os.listdir(target_dir)
        ):
            return False, f"target already populated: {path} (use --force to overwrite)"

        os.makedirs(MODULES_DIR, exist_ok=True)

        # sha256 is semi-mandatory for tar archives: warn loudly (twice) before download
        if mod_type == "tar" and not sha:
            warn(f"SECURITY: repository index provides no sha256 for '{name}' — download cannot be verified")
            warn("SECURITY: proceeding UNVERIFIED — inspect the source before trusting this module")

        if mod_type == "tar":
            success = self._install_tar(url, target_dir, expected_sha256=sha)
        elif mod_type == "git":
            success = self._install_git(url, module_info.get("branch", "main"), target_dir)
        else:
            return False, f"unknown module type: {mod_type!r}"

        if not success:
            return False, "install failed (see errors above)"

        # TOFU: register every installed .py as untrusted
        if trust_mgr is not None:
            self._register_installed(target_dir, module_info, trust_mgr)

        return True, ""

    def _register_installed(self, target_dir: str, module_info: dict, trust_mgr):
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if not d.startswith((".", "__"))]
            for fn in files:
                if not fn.endswith(".py") or fn.startswith(("_", "@")):
                    continue
                fpath = os.path.join(root, fn)
                rel = os.path.relpath(fpath, MODULES_DIR).replace(os.sep, "/")
                key = rel[:-3]
                trust_mgr.register_untrusted(
                    key, fpath,
                    source="remote",
                    remote_url=module_info.get("_repo_url"),
                    module_name=module_info.get("name"),
                    version=module_info.get("version"),
                )

    def _install_tar(self, url: str, target_dir: str, expected_sha256: str = None) -> bool:
        staging   = f"{target_dir}.staging-{int(time.time())}"
        temp_file = os.path.join(
            CACHE_DIR,
            f"dl_{hashlib.sha256(url.encode()).hexdigest()[:12]}_{int(time.time())}.tar",
        )
        try:
            if not _safe_download(url, temp_file, MAX_ARCHIVE_SIZE, DOWNLOAD_TIMEOUT):
                return False

            if expected_sha256:
                actual = sha256_of_path(temp_file)
                if actual.lower() != expected_sha256.lower():
                    err(f"SHA256 mismatch: got {actual[:16]}… expected {expected_sha256[:16]}…")
                    return False

            try:
                with tarfile.open(temp_file, "r:*") as tar:
                    _safe_extract_tar(tar, staging)
            except (tarfile.TarError, OSError):
                with open(temp_file, "rb") as fh:
                    dctx = zstd.ZstdDecompressor()
                    with dctx.stream_reader(fh) as reader:
                        with tarfile.open(fileobj=reader, mode="r|") as tar:
                            _safe_extract_tar(tar, staging)

            if os.path.exists(target_dir):
                shutil.rmtree(target_dir, ignore_errors=True)
            os.rename(staging, target_dir)
            return True
        except Exception as e:
            err(f"Tar install failed: {e}")
            return False
        finally:
            for p in (temp_file, staging):
                if os.path.exists(p):
                    try:
                        if os.path.isdir(p):
                            shutil.rmtree(p, ignore_errors=True)
                        else:
                            os.remove(p)
                    except OSError:
                        pass

    def _install_git(self, url: str, branch: str, target_dir: str) -> bool:
        staging = f"{target_dir}.staging-{int(time.time())}"
        backup  = f"{target_dir}.bak-{int(time.time())}"
        try:
            os.makedirs(os.path.dirname(target_dir) or ".", exist_ok=True)
            if os.path.exists(staging):
                shutil.rmtree(staging, ignore_errors=True)

            # only HTTPS transports — blocks ext:: and other helper transports
            if not url.lower().startswith("https://"):
                err("Git install failed: only HTTPS URLs are allowed")
                return False

            proc = subprocess.run(
                ["git", "clone", "-b", branch, "--depth", "1",
                 "--config", "protocol.ext.allow=never", "--", url, staging],
                capture_output=True, text=True, timeout=DOWNLOAD_TIMEOUT,
            )
            if proc.returncode != 0:
                err(f"Git clone failed: {(proc.stderr or '').strip()[:200]}")
                return False

            if os.path.exists(target_dir):
                os.rename(target_dir, backup)
            try:
                os.rename(staging, target_dir)
            except OSError:
                if os.path.exists(backup):
                    os.rename(backup, target_dir)
                raise

            if os.path.exists(backup):
                shutil.rmtree(backup, ignore_errors=True)
            return True
        except subprocess.TimeoutExpired:
            err(f"Git clone timed out after {DOWNLOAD_TIMEOUT}s")
            return False
        except Exception as e:
            err(f"Git install failed: {e}")
            if os.path.exists(backup) and not os.path.exists(target_dir):
                try:
                    os.rename(backup, target_dir)
                except OSError:
                    pass
            return False
        finally:
            if os.path.exists(staging):
                shutil.rmtree(staging, ignore_errors=True)

    # ── stats ───────────────────────────────────────────────
    def stats(self) -> dict:
        all_mods   = self.get_all_modules()
        cache_size = 0
        if os.path.isdir(CACHE_DIR):
            for entry in os.listdir(CACHE_DIR):
                p = os.path.join(CACHE_DIR, entry)
                if os.path.isfile(p):
                    try:
                        cache_size += os.path.getsize(p)
                    except OSError:
                        pass
        return {
            "remotes":      len(self.remotes),
            "enabled":      sum(1 for r in self.remotes if r.get("enabled", True)),
            "modules":      len(all_mods),
            "cache_bytes":  cache_size,
        }