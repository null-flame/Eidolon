# Default C2 modules (bundled, NOT auto-installed)

The Eidolon kernel ships zero capability. By design nothing here is planted
into `~/.eidolon/modules` for you: the scanner ignores this folder, and the
framework never trusts anything you did not inspect. These are two
production-quality reference modules — the small-kernel equivalent of "canon
loadout" — you install explicitly:

```
install_local default-modules/ws-mtls-listener
install_local default-modules/poly-builder
trust ws-mtls-listener
trust poly-builder
```

`install_local` / `add_module` ship exactly the assets a module declares in its
module-level `ASSETS` list — files or directories, relative to the module file
(e.g. `ASSETS = ("_src",)` copy the whole `_src/` tree: `implant.go`,
`implant.nim`, …). Nothing else is ever copied: no `__pycache__`, no hidden
files, no undeclared neighbors. Anything declared but missing on disk is
reported and skipped. If the module file is already registered (no `--force`),
the module copy is skipped but declared assets are still refreshed.

(Or serve this repo as an index with `repo` and install both like any other
remote module — TOFU applies either way.)

## The pair

| module | role |
| --- | --- |
| `ws-mtls-listener` | listener — WebSocket over TLS (`wss`), mTLS implants, publishes a build profile |
| `poly-builder` | payload — renders + compiles the bundled implants (`_src/implant.go`, `_src/implant.nim`), registers the artifact |

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
