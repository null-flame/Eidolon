# Default C2 modules (bundled, NOT auto-installed)

The Eidolon kernel ships zero capability. By design nothing here is planted
into `~/.eidolon/modules` for you: the scanner ignores this folder, and the
framework never trusts anything you did not inspect. These are three
production-quality reference modules — the small-kernel equivalent of "canon
loadout" — you install explicitly:

```
install_local default-modules/ws-mtls-listener
install_local default-modules/poly-builder
trust ws-mtls-listener
trust poly-builder
```

`install_local default-modules/rubika` ships the third module in the same
directory form — `rubika_member_transfer`; install and trust it the same way:

`install_local` / `add_module` ship exactly the assets a module declares in its
module-level `ASSETS` list — files or directories, relative to the module file
(e.g. `ASSETS = ("_src",)` copy the whole `_src/` tree: `implant.go`,
`implant.nim`, …). Nothing else is ever copied: no `__pycache__`, no hidden
files, no undeclared neighbors. Anything declared but missing on disk is
reported and skipped. If the module file is already registered (no `--force`),
the module copy is skipped but declared assets are still refreshed.

(Or serve this repo as an index with `repo` and install both like any other
remote module — TOFU applies either way.)

## The loadout

| module | role |
| --- | --- |
| `ws-mtls-listener` | listener — WebSocket over TLS (`wss`), mTLS implants, publishes a build profile |
| `poly-builder` | payload — renders + compiles the bundled implants (`_src/implant.go`, `_src/implant.nim`), registers the artifact |
| `rubika_member_transfer` | auxiliary — Rubika messenger ops on a maxrubika userbot session: transfer members between your groups and channels (group/channel in and out), view members (`view <id>` with channel pagination), chat info (`info <id>`, `whoami`); inner subshell, `/setsource` / `/settarget` / `/transfer` triggers in chat |
| `ssghost` | auxiliary — OBSIDIAN VANGUARD official: one engage pass rewrites a Rubika group/channel identity (title, bio, avatar wipe + upload), fine-tunes every editable section (group: slow mode, reactions, restricted content; channel: username, Public/Private, signed messages, restricted content — each field applied on its own, a refused field never stops the pass) and purges every member while exempting admins, bots and the session itself; the ban engine runs unlimited waves until the purge list is empty (any chat size is swept past the ~100-member fetch cap; a no-progress fuse stops the loop) with a configurable chunk size (`chunk`); group event messages are silenced for the pass by default (`quiet_mode=True`, restored after, graceful without permission) and every ban is lifted when the pass ends (`unban_after=True` by default); identities (title + bio + avatar) save to a local profile vault and apply by name (`profile save <n>` / `profile <n>`); `dry_run` is OFF by default (LIVE — every `engage` fires for real; `set dry_run True` for a rehearsal pass); subshell `target / engage / rebrand / profile / chunk / settings / quiet / real / unban / banned / admins` + in-chat trigger `/ssghost` (full pass) or `/ssghost <profile>` (identity pass, session-owner gated); works on `g0` and `c0` alike |

Operator flow end to end:

```
use ws-mtls-listener
  set port 8443
  run                              # certs generated once in _certs/, job backgrounds, token printed
gen poly-builder                   # picks up the live listener profile
  set lang go
  set name corp-implant
  run                              # artifact lands in YOUR cwd, registered with keep=True
sessions                           # implants show up as wraith sessions on connect
use <sid>                          # inner shell: shell / sysinfo / upload / download / die
```

## Dependencies (module-owned)

The framework installs nothing, ever. Each module guards its own imports:

- listener: `pip install websockets>=13 cryptography>=42`
- `poly-builder` + `lang=go`: a Go toolchain (`go` on PATH; stdlib-only implant, cross-compiles natively)
- `poly-builder` + `lang=nim`: the Nim toolchain (`nim` on PATH; build flags include `-d:ssl` — Windows targets need the OpenSSL binaries next to the artifact or in the search path)
- nim cross-compiling linux→windows is refused with guidance; build on the target OS or wire a cross toolchain yourself
- `rubika_member_transfer` + `ssghost`: a maxrubika session (`pip install maxrubika`)

## Wire protocol (`ws-json-mtls/1`)

One JSON object per WebSocket text frame:

- hello (implant → listener): `{"id","implant","os","arch","user","host","token"}`
- command (listener → implant): `{"id","cmd":"shell|sysinfo|upload|download|die","arg"/"path","data"(b64)}`
- reply: `{"id","type":"result","out"}` or `{"id","type":"dl","path","data"}`

The profile published by `ws-mtls-listener` (`EIDOLON_SHELL.wraith_listener`)
carries `url`, `token`, `tags` and the cert paths (`ca_crt`, `client_crt`,
`client_key`) — `poly-builder` bakes all of it into every artifact. Nothing is
sent over the wire that the implant could not have read from its own binary.

## Security design (what actually protects you)

- **mTLS is the identity**: module-generated CA (12y), server cert with SANs
  for localhost + the bound IP, client cert (EKU clientAuth) → only implants
  built through the builder can even complete the TLS handshake.
- **Shared token on top**: a wrong token with a VALID client cert is logged as
  a `warn` (cert-theft signal), not a silent drop.
- **Caps everywhere**: frames ≤ 4 MiB (`ws max_size`), download cap 4 MiB,
  10 s hello window, 120 s shell exec timeout (Go), 5–8 s jittered reconnect.
- **No temp artifacts**: builder output goes to the operator's cwd or an
  explicit `output` path, 0o700, registered with `keep=True` — the store's
  `/tmp|/var/tmp|/dev/shm|%TEMP%` refusal never has to fire.
- **Underscore dirs are invisible to the scanner** (`_src/`, `_certs/`, …):
  raw implant sources and lifetimes of key material live outside the module
  index. Copies of the client key are a compromise: regenerate with
  `set regenerate true` (or wipe `cert_dir`) after any incident.

## Test matrix so far

- Go implant: compile-verified for `GOOS=linux` and `GOOS=windows` (`go1.27`,
  stdlib-only).
- Nim implant: source-reviewed (stdlib-only, manual WS framing, `CVerifyPeer`);
  compile it once with `nim c -d:release -d:ssl --opt:size` — the CI sandbox
  has no Nim toolchain.
- Python modules: `py_compile` clean; import smoke-tested with injected
  kernel globals (guardrails: missing name/lang/listener all produce clean
  `err()` messages).
- `rubika_member_transfer`: `py_compile` clean; import smoke-tested with a
  stub maxrubika client (channel pagination via `start_id`, bot/dup filtering,
  batched `add_members`, subshell commands).
- `ssghost`: `py_compile` clean; smoke-tested (19 cases) with a stub maxrubika client:
  dry-run gatekeeping, live group/channel purge, chunked bans, unlimited-wave
  termination + no-progress fuse, rate-limit guard, `event_messages=False`→`True`
  quiet cycle (default ON, graceful without permission), granular settings blade
  for group and channel fields incl. refusals and 32-char username truncation,
  profile vault save/apply/del, trigger parsing incl. `/ssghost <profile>` negatives,
  chunk/quiet knobs, avatar path hygiene (quotes, `~`).
