import os
import json
import urllib.request
import tarfile
import subprocess
import shutil
import time
import zstandard as zstd
from pathlib import Path
from eidolon.utils import spectral, err, ok, warn

WORKSPACE_DIR = os.path.join(os.path.expanduser("~"), ".eidolon")
REPOS_FILE = os.path.join(WORKSPACE_DIR, "remotes.json")
CACHE_DIR = os.path.join(WORKSPACE_DIR, "cache")
MODULES_DIR = os.path.join(WORKSPACE_DIR, "modules")

DEFAULT_REPO = "https://raw.githubusercontent.com/null-flame/Eidolon/refs/heads/main/modules.json"

class RepositoryManager:
    def __init__(self):
        os.makedirs(CACHE_DIR, exist_ok=True)
        self.remotes = self._load_remotes()

    def _load_remotes(self):
        if not os.path.exists(REPOS_FILE):
            default_data = [{"url": DEFAULT_REPO, "enabled": True, "priority": 10}]
            self._save_remotes(default_data)
            return default_data
        try:
            with open(REPOS_FILE, 'r') as f:
                data = json.load(f)
                # Migration: If old format (list of strings), upgrade to dict
                if data and isinstance(data[0], str):
                    data = [{"url": u, "enabled": True, "priority": 10} for u in data]
                    self._save_remotes(data)
                return data
        except Exception:
            return [{"url": DEFAULT_REPO, "enabled": True, "priority": 10}]

    def _save_remotes(self, remotes):
        with open(REPOS_FILE, 'w') as f:
            json.dump(remotes, f, indent=2)

    def add_remote(self, url):
        if any(r["url"] == url for r in self.remotes):
            return False
        self.remotes.append({"url": url, "enabled": True, "priority": 10})
        self._save_remotes(self.remotes)
        return True

    def remove_remote(self, url):
        initial_len = len(self.remotes)
        self.remotes = [r for r in self.remotes if r["url"] != url]
        if len(self.remotes) < initial_len:
            self._save_remotes(self.remotes)
            return True
        return False

    def toggle_remote(self, url, enable=True):
        for r in self.remotes:
            if r["url"] == url:
                r["enabled"] = enable
                self._save_remotes(self.remotes)
                return True
        return False

    def set_priority(self, url, priority):
        for r in self.remotes:
            if r["url"] == url:
                r["priority"] = int(priority)
                self._save_remotes(self.remotes)
                return True
        return False

    def sync_json(self, force_refresh=True):
        """Only updates the cached modules.json files from enabled remotes."""
        count = 0
        for r in self.remotes:
            if not r.get("enabled", True):
                continue
            url = r["url"]
            cache_file = os.path.join(CACHE_DIR, os.path.basename(url))
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Eidolon-Framework'})
                with urllib.request.urlopen(req, timeout=10) as response:
                    data = json.loads(response.read().decode('utf-8'))
                    with open(cache_file, 'w') as f:
                        json.dump(data, f)
                    count += 1
            except Exception as e:
                warn(f"Failed to sync {url}: {e}")
        return count

    def fetch_repo_json(self, url, force_refresh=False):
        cache_file = os.path.join(CACHE_DIR, os.path.basename(url))
        if not force_refresh and os.path.exists(cache_file):
            if time.time() - os.path.getmtime(cache_file) < 3600:
                with open(cache_file, 'r') as f:
                    return json.load(f)
        
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Eidolon-Framework'})
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
                with open(cache_file, 'w') as f:
                    json.dump(data, f)
                return data
        except Exception as e:
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    return json.load(f)
            return None

    def get_all_modules(self, force_refresh=False):
        all_modules = {}
        # Sort remotes by priority (higher number = higher priority)
        sorted_remotes = sorted(
            [r for r in self.remotes if r.get("enabled", True)],
            key=lambda x: x.get("priority", 10),
            reverse=True
        )
        
        for r in sorted_remotes:
            url = r["url"]
            data = self.fetch_repo_json(url, force_refresh)
            if data and 'modules' in data:
                for mod in data['modules']:
                    mod['_repo_url'] = url
                    # Overwrite if in lower priority repo (since we iterate high to low)
                    if mod['name'] not in all_modules:
                        all_modules[mod['name']] = mod
        return all_modules

    def install_module(self, module_info):
        name = module_info['name']
        path = module_info.get('path', name)
        mod_type = module_info.get('type', 'tar')
        url = module_info.get('url')
        
        target_dir = os.path.join(MODULES_DIR, path)
        os.makedirs(target_dir, exist_ok=True)

        if mod_type == 'tar':
            return self._install_tar(url, target_dir)
        elif mod_type == 'git':
            return self._install_git(url, module_info.get('branch', 'main'), target_dir)
        return False

    def _install_tar(self, url, target_dir):
        try:
            temp_file = os.path.join(CACHE_DIR, "temp_download.tar")
            req = urllib.request.Request(url, headers={'User-Agent': 'Eidolon-Framework'})
            with urllib.request.urlopen(req) as response, open(temp_file, 'wb') as out_file:
                shutil.copyfileobj(response, out_file)
            
            if url.endswith('.zst') or url.endswith('.tar.zst'):
                with open(temp_file, 'rb') as fh:
                    dctx = zstd.ZstdDecompressor()
                    with dctx.stream_reader(fh) as reader:
                        with tarfile.open(fileobj=reader, mode='r|') as tar:
                            tar.extractall(path=target_dir)
            else:
                with tarfile.open(temp_file, 'r:*') as tar:
                    tar.extractall(path=target_dir)
            
            os.remove(temp_file)
            return True
        except Exception as e:
            err(f"Tar install failed: {e}")
            return False

    def _install_git(self, url, branch, target_dir):
        try:
            if os.path.exists(target_dir):
                shutil.rmtree(target_dir)
            subprocess.run(['git', 'clone', '-b', branch, '--depth', '1', url, target_dir], check=True, capture_output=True)
            return True
        except Exception as e:
            err(f"Git clone failed: {e}")
            return False