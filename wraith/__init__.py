"""
Wraith — the C2 subsystem of Eidolon.

A lightweight, self-contained command-and-control layer that lives beside the
exploit framework without touching it:

  * wraith/protocol.py  — JSON-over-WebSocket wire protocol (specs + validation)
  * wraith/sessions.py  — thread-safe in-memory session registry
  * wraith/listener.py  — fully async listener (own loop + thread), TLS, auth
  * wraith/store.py     — typed payload store + type-filtered resolution

There is NO built-in payload source and NO built-in builder in the framework.
A payload builder is just an ordinary module of type "payload": its sources
live with the module, its python script compiles/produces the payload in any
language it likes (go, nim, c, rust, c#, bash, python, …) with the operator
profile embedded, and it places the artifact in the typed store via
`wraith.store.register_payload(...)`. Exploit modules consume payloads by
name through the `"kind": "payload"` option field (type-filtered by the
store) — the exploit only delivers; the payload dials the listener home.

Philosophy (unchanged): exploits deliver, Wraith receives.

Requires `websockets>=11` (only install-time dep; TLS is optional via
`cryptography`).
"""

__version__ = "0.2.0-c2.2"

__all__ = ["protocol", "sessions", "listener", "store"]


def __getattr__(name):
    if name in ("protocol", "sessions", "listener", "store"):
        import importlib

        return importlib.import_module(f"wraith.{name}")
    raise AttributeError(f"module 'wraith' has no attribute '{name}'")
