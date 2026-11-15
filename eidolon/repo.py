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
            self._save_remotes([DEFAULT_REPO])
            return [DEFAULT_REPO]
        try:
            with open(REPOS_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return [DEFAULT_REPO]

    def _save_remotes(self, remotes):
        with open(REPOS_FILE, 'w') as f:
            json.dump(remotes, f, indent=2)

    def add_remote(self, url):
        if url in self.remotes:
            return False
        self.remotes.append(url)
        self._save_remotes(self.remotes)
        return True

    def remove_remote(self, url):
        if url in self.remotes:
            self.remotes.remove(url)
            self._save_remotes(self.remotes)
            return True
        return False

    def fetch_repo_json(self, url, force_refresh=False):
        cache_file = os.path.join(CACHE_DIR, os.path.basename(url))
        if not force_refresh and os.path.exists(cache_file):
            # Cache for 1 hour
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
                warn(f"Failed to fetch {url}, using stale cache. Error: {e}")
                with open(cache_file, 'r') as f:
                    return json.load(f)
            err(f"Failed to fetch {url}: {e}")
            return None

    def get_all_modules(self, force_refresh=False):
        all_modules = {}
        for url in self.remotes:
            data = self.fetch_repo_json(url, force_refresh)
            if data and 'modules' in data:
                for mod in data['modules']:
                    mod['_repo_url'] = url
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
        else:
            err(f"Unknown module type: {mod_type}")
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
        except subprocess.CalledProcessError as e:
            err(f"Git clone failed: {e.stderr.decode()}")
            return False
        except FileNotFoundError:
            err("Git is not installed on this system.")
            return False