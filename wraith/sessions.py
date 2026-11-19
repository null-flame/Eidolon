"""Session registry — thread-safe, in-memory, bounded result history."""

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

RESULT_HISTORY = 64

_default_registry = None


def default_registry():
    """Process-wide shared registry.

    Listener modules that register sessions here get free integration with
    the framework's `c2 sessions` / `c2 status` views — and, if the listener
    module attaches a callable to a session's `interact` attribute, the
    framework's `use <sid>` command hands the console straight to it (the
    module owns the inner shell, its prompt and its tab completion). Modules
    may equally keep a private SessionRegistry — the kernel only offers,
    never imposes.
    """
    global _default_registry
    if _default_registry is None:
        _default_registry = SessionRegistry()
    return _default_registry


@dataclass
class Session:
    sid: str
    implant: str
    os: str
    arch: str
    user: str
    host: str
    addr: str
    connected_at: float
    last_seen: float
    tags: tuple = ()
    status: str = "active"
    results: deque = field(default_factory=lambda: deque(maxlen=RESULT_HISTORY))
    pending: int = 0
    interact: object = None  # module-side ONLY: callable(EIDOLON_SHELL) — `use <sid>` hands over (prompt, commands, tab completion: all module business)

    @property
    def label(self):
        return f"{self.user}@{self.host} ({self.implant}/{self.os}-{self.arch})"


class SessionRegistry:
    def __init__(self):
        self._sessions = {}
        self._lock = threading.RLock()

    def register(self, info: dict, addr: str) -> Session:
        now = time.time()
        sess = Session(
            sid=info.get("sid"),
            implant=info.get("implant", "unknown"),
            os=info.get("os", "unknown"),
            arch=info.get("arch", "unknown"),
            user=info.get("user", "unknown"),
            host=info.get("host", "unknown"),
            addr=str(addr),
            tags=tuple(info.get("tags") or ()),
            connected_at=now,
            last_seen=now,
        )
        with self._lock:
            self._sessions[sess.sid] = sess
        return sess

    def get(self, sid) -> Optional[Session]:
        with self._lock:
            return self._sessions.get(sid)

    def find(self, prefix) -> Optional[Session]:
        with self._lock:
            matches = [s for s in self._sessions.values() if s.sid.startswith(prefix)]
        if not matches:
            return None
        if len(matches) > 1:
            raise ValueError(f"ambiguous session prefix: {prefix} ({len(matches)} matches)")
        return matches[0]

    def touch(self, sid):
        with self._lock:
            s = self._sessions.get(sid)
            if s:
                s.last_seen = time.time()
                s.status = "active"

    def mark_lost(self, sid):
        with self._lock:
            s = self._sessions.get(sid)
            if s:
                s.status = "lost"

    def forget(self, sid) -> bool:
        with self._lock:
            return self._sessions.pop(sid, None) is not None

    def all(self):
        with self._lock:
            return sorted(self._sessions.values(), key=lambda s: s.connected_at)

    def active(self):
        return [s for s in self.all() if s.status == "active"]

    def counts(self):
        with self._lock:
            total = len(self._sessions)
        active = len(self.active())
        return {"total": total, "active": active, "lost": total - active}
