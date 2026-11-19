"""
Wraith — the C2 subsystem of Eidolon.

A lightweight, self-contained command-and-control layer that lives beside the
exploit framework without touching it:

  * wraith/protocol.py  — JSON-over-WebSocket wire protocol (specs + validation)
  * wraith/sessions.py  — thread-safe in-memory session registry
  * wraith/listener.py  — fully async listener (own loop + thread), TLS, auth
  * wraith/builder.py   — compiles payloads with the operator profile embedded
  * wraith/store.py     — typed payload store + type-filtered resolution

Philosophy (unchanged): exploits deliver, Wraith receives. An exploit module
never talks to the C2 directly — it optionally takes a payload through
`wraith.store.resolve_payload()` (type-filtered) and simply executes it; the
compiled payload dials the listener home.

Requires `websockets>=11` (only install-time dep; TLS is optional via
`cryptography`).
"""

__version__ = "0.1.0-c2.1"

__all__ = ["protocol", "sessions", "listener", "builder", "store"]


def __getattr__(name):
    if name in ("protocol", "sessions", "listener", "builder", "store"):
        import importlib

        return importlib.import_module(f"wraith.{name}")
    raise AttributeError(f"module 'wraith' has no attribute '{name}'")
