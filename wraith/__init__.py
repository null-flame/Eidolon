"""
Wraith — the C2 kernel of Eidolon.

A minimal, dependency-free SDK that lets user-written modules assemble a full
command-and-control layer WITHOUT the framework shipping any of it:

  * wraith/protocol.py  — JSON wire spec + validation (transport-agnostic)
  * wraith/sessions.py  — thread-safe session registry (+ shared default_registry())
  * wraith/store.py     — typed payload store + type-filtered resolution

There is NO listener, NO payload source and NO builder in the framework.
Everything that actually runs is an ordinary module written by anyone:

  * a LISTENER module (MODULE_TYPE "listener") starts a server with whatever
    transport and its own libraries it likes (ws, tcp, http, …), registers sessions
    into wraith.sessions.default_registry(), exposes its profile through
    EIDOLON_SHELL.wraith_listener (url / token / tags), and defines stop().
    `gen <module>` / `run --bg` turn it into a managed background job.
  * a PAYLOAD module (MODULE_TYPE "payload") is the builder: its internal
    layout is entirely free (sources may live in _src/, anywhere), its python
    entry script compiles the artifact in ANY language with the listener
    profile embedded, and registers it via wraith.store.register_payload(...).

Exploits consume payloads through the dedicated `"kind": "payload"` option
field — validated on set against the declared types, then handed to run() as
a manifest dict with a "path" key.

Philosophy: the kernel defines the shared tongue and the shelves; modules do
everything else. Exploits deliver, the listener receives.

Listener transports are module business: the only hard requirements are the
wire contract a payload speaks (protocol.py) and the shelves (sessions/store).
"""

__version__ = "0.3.0-c2.3"

__all__ = ["protocol", "sessions", "store"]


def __getattr__(name):
    if name in ("protocol", "sessions", "store"):
        import importlib

        return importlib.import_module(f"wraith.{name}")
    raise AttributeError(f"module 'wraith' has no attribute '{name}'")
