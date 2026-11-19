"""
Wraith — the C2 kernel of Eidolon.

A minimal, dependency-free SDK that lets user-written modules assemble a full
command-and-control layer WITHOUT the framework shipping any of it:

  * wraith/sessions.py  — thread-safe session registry (+ shared default_registry())
  * wraith/store.py     — typed payload store + type-filtered resolution

That is the whole kernel: two files, no wire contract, no protocol document,
no transport code. There is NO listener, NO payload source and NO builder in
the framework. Everything that actually runs is an ordinary module written by
anyone — the internal layout of a module is entirely free (sources in _src/,
siblings, assets, whatever the author wants; the framework knows only the
module's entry script), and every capability (remote shell, screenshot, file
transfer, …) is purely an AGREEMENT between a listener module and the payload
built to speak to it.

  * a LISTENER module (MODULE_TYPE "listener") starts a server with whatever
    transport and libraries it likes (ws, tcp, http, grpc, …), registers
    sessions into wraith.sessions.default_registry(), publishes its operating
    profile through EIDOLON_SHELL.wraith_listener (url / token / tags) and
    defines stop(). A selected listener starts with `run` — it automatically
    becomes a managed background job. A module may attach an `interact`
    callable to each session: `use <sid>` then hands the console to it —
    prompt, inner commands and TAB COMPLETION are all module business.
  * a PAYLOAD module (MODULE_TYPE "payload") is the builder: its python entry
    script compiles the artifact in ANY language, embeds whatever the payload
    needs, and registers it via wraith.store.register_payload(...). `gen
    <module>` selects it; parameters come from `set` like any exploit; `run`
    builds and reports what hit the store.

Exploits consume payloads through the dedicated `"kind": "payload"` option
field — validated on set against the declared types, then handed to run() as
a manifest dict with a "path" key.

Philosophy: the kernel offers the shelves; modules do everything else.
Exploits deliver, the listener receives — on any wire they agree on.
"""

__version__ = "0.4.0-c2.4"

__all__ = ["sessions", "store"]


def __getattr__(name):
    if name in ("sessions", "store"):
        import importlib

        return importlib.import_module(f"wraith.{name}")
    raise AttributeError(f"module 'wraith' has no attribute '{name}'")
