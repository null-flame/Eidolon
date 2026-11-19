"""Typed payload store — built payloads live here, labeled with a type so a
payload can never be swapped into a delivery path that does not fit.

This is the kernel's only opinion about payloads: they have a TYPE (so the
wrong artifact cannot slip into a delivery path silently) and nothing else is
imposed — wire format, transport, handshake, encodings and limits are entirely
between a listener module and the payload the operator builds for it.

Layout: ~/.eidolon/payloads/<name>/{manifest.json, <artifact>}
Manifest: {"name","type","backend","os","arch","created","file","sha256","note","protocol"}

Types (advisory taxonomy — delivery is always the module author's business):
  file-posix : compiled runnable artifact for POSIX targets (ELF / mach-o)
  file-win   : compiled runnable artifact for Windows targets (PE)
  shellcode  : raw position-independent machine code
  cmd        : a command line the target's shell executes
  code       : source executed by an interpreter on the target

The primary route for exploit modules is the DEDICATED payload field — declare
an option with `"kind": "payload"` (+ the accepted `"types"`) and the framework
validates on `set` and hands run() a manifest dict with "path" inside:

    OPTIONS = {"payload": {"value": "", "kind": "payload",
                           "types": ("file-posix", "file-win")}}
    def run(opts):
        artifact = opts["payload"]["path"]

Underneath sits `resolve_payload`, which accepts a store name or any filesystem
path; store payloads are type-validated against `kinds`, external files are
reported as type "external" so the module can decide (or reject with a clear
error). Payload-BUILDER modules (type "payload") place artifacts here via
`register_payload`.
"""

import hashlib
import json
import os
import shutil
import time

WORKSPACE_DIR = os.path.join(os.path.expanduser("~"), ".eidolon")
STORE_DIR = os.path.join(WORKSPACE_DIR, "payloads")

TYPE_FILE_POSIX = "file-posix"
TYPE_FILE_WIN = "file-win"
TYPE_SHELLCODE = "shellcode"
TYPE_CMD = "cmd"
TYPE_CODE = "code"
TYPE_EXTERNAL = "external"

PAYLOAD_TYPES = (TYPE_FILE_POSIX, TYPE_FILE_WIN, TYPE_SHELLCODE, TYPE_CMD, TYPE_CODE)


def _tags_str(tags):
    if not tags:
        return ""
    if isinstance(tags, str):
        return tags.strip()
    return ";".join(str(t).strip() for t in tags if str(t).strip())


def _manifest_path(name):
    return os.path.join(STORE_DIR, name, "manifest.json")


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def store_path(name=None):
    if name is not None:
        if os.sep in name or "/" in name or name.startswith("."):
            raise ValueError(f"invalid payload name: {name!r}")
        return os.path.join(STORE_DIR, name)
    return STORE_DIR


def list_payloads():
    """All stored payloads: {name: manifest} sorted by creation time."""
    found = {}
    if not os.path.isdir(STORE_DIR):
        return found
    for name in sorted(os.listdir(STORE_DIR)):
        mpath = _manifest_path(name)
        if not os.path.isfile(mpath):
            continue
        try:
            with open(mpath, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception:
            continue
        found[manifest.get("name", name)] = manifest
    return dict(sorted(found.items(), key=lambda kv: kv[1].get("created", 0)))


def register_payload(name, artifact_path, ptype, backend=None, target_os=None,
                     arch=None, note=None, protocol_tag=None, config=None):
    """Move an artifact into the store and write its typed manifest.

    Returns the manifest dict. Raises on a bad type or a missing artifact.
    `protocol_tag` is OPTIONAL free metadata (a single tag like
    "ws-json-async" or several) — purely informational: it labels which wire
    dialect the artifact was built to speak so c2 payloads / any module can
    display or filter on it. The kernel never connects anything itself, so it
    never enforces a handshake.
    `config` is the OPTIONAL build-time configuration (any dict, e.g. the
    builder's OPTIONS values the operator set via gen/set) — carried along
    in the manifest so exploits read the payload's setup directly from its
    output.
    """
    if ptype not in PAYLOAD_TYPES:
        raise ValueError(
            f"unknown payload type: {ptype!r} (valid: {', '.join(PAYLOAD_TYPES)})"
        )
    artifact_path = os.path.abspath(artifact_path)
    if not os.path.isfile(artifact_path):
        raise FileNotFoundError(artifact_path)

    target_dir = store_path(name)
    os.makedirs(target_dir, exist_ok=True)
    dest = os.path.join(target_dir, os.path.basename(artifact_path))
    if os.path.abspath(artifact_path) != os.path.abspath(dest):
        shutil.move(artifact_path, dest)

    manifest = {
        "name": name,
        "type": ptype,
        "backend": backend or "",
        "os": target_os or "",
        "arch": arch or "",
        "created": time.time(),
        "file": os.path.basename(dest),
        "sha256": _sha256(dest),
        "note": note or "",
        "protocol": _tags_str(protocol_tag),
        "config": dict(config) if config else {},
    }
    with open(_manifest_path(name), "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    return manifest


def remove_payload(name):
    target_dir = store_path(name)
    if not os.path.isdir(target_dir):
        return False
    shutil.rmtree(target_dir, ignore_errors=True)
    return True


def artifact_path(manifest):
    return os.path.join(STORE_DIR, manifest["name"], manifest.get("file", ""))


def payload_types(ref):
    """Type label for a payload reference (store name or raw path). Store
    payloads return their manifest type; unknown external files return
    TYPE_EXTERNAL."""
    if os.path.isfile(ref):
        return [TYPE_EXTERNAL]
    manifest = list_payloads().get(ref)
    if manifest:
        return [manifest.get("type", TYPE_EXTERNAL)]
    return []


def resolve_payload(ref, kinds=None, quiet=False):
    """Resolve a payload reference for an exploit module, with type filtering.

    ref    — a store payload name, or any filesystem path (operator-supplied raw
             file, shellcode, script… — full freedom, no store required)
    kinds  — optional iterable of types this delivery accepts; store payloads
             outside `kinds` are refused, external files pass with type
             TYPE_EXTERNAL so the module stays authoritative

    Returns (path, manifest). Raises ValueError with an actionable message on
    mismatch — never silently mix a wrong payload into a delivery.
    """
    if ref is None or not str(ref).strip():
        raise ValueError("no payload given — set the PAYLOAD option to a name or path")
    ref = str(ref).strip()

    if ref in list_payloads():
        manifest = list_payloads()[ref]
        path = artifact_path(manifest)
        if not os.path.isfile(path):
            raise ValueError(f"stored payload {ref!r} is missing its artifact "
                             f"({manifest.get('file', '?')})")
        if kinds and manifest.get("type") not in kinds:
            raise ValueError(
                f"payload {ref!r} is type {manifest.get('type')!r} but this module "
                f"accepts {sorted(kinds)} — pick a matching payload"
            )
        return path, manifest

    if os.path.isfile(ref):
        return os.path.abspath(ref), {"name": os.path.basename(ref), "type": TYPE_EXTERNAL,
                                      "file": os.path.basename(ref)}

    raise ValueError(f"payload not found: {ref!r} — check `c2 payloads` or give a file path")


def summary(manifest):
    """One-line human summary of a manifest for console output."""
    mtype = manifest.get("type", "?")
    meta = " · ".join(x for x in (
        manifest.get("backend") or "",
        (f"{manifest.get('protocol')}" if manifest.get("protocol") else ""),
        (f"{manifest['os']}/{manifest['arch']}" if manifest.get("os") else ""),
    ) if x)
    tail = f" ({meta})" if meta else ""
    cfg = manifest.get("config") or {}
    if cfg:
        tail += (" · " if meta else " (") + f"config: {len(cfg)}" + ("" if meta else ")")
    return f"{manifest.get('name', '?')} [{mtype}]{tail}"
