//go:build linux

package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	iocTIOCGPTN   = 0x80045430 // get pty slave number
	iocTIOCSPTLCK = 0x40045431 // unlock pty slave
	iocSetWinsize = 0x5414     // set terminal size
	iocTrapAmd64  = 16         // SYS_IOCTL — linux/amd64
	iocTrapArm64  = 29         // SYS_IOCTL — linux/arm64
)

func sysIoctl(fd, req, arg uintptr) error {
	trap := uintptr(iocTrapAmd64)
	if runtime.GOARCH == "arm64" {
		trap = uintptr(iocTrapArm64)
	}
	if _, _, errno := syscall.Syscall(trap, fd, req, arg); errno != 0 {
		return errno
	}
	return nil
}

func ptySetSize(arg string) error {
	ptyMu.Lock()
	p := activePty
	ptyMu.Unlock()
	if p == nil {
		return fmt.Errorf("no pty up")
	}
	cols, rows := ptyTermSize(arg)
	var wsz struct{ Row, Col, X, Y uint16 }
	wsz.Row, wsz.Col = rows, cols
	return sysIoctl(p.master.Fd(), iocSetWinsize, uintptr(unsafe.Pointer(&wsz)))
}

func ptyOpen(id int64, arg string, conn net.Conn) {
	ptyMu.Lock()
	prev := activePty
	ptyMu.Unlock()
	if prev != nil {
		prev.kill()
	}

	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		sendText(conn, ptyResult(id, "pty: open /dev/ptmx failed: "+err.Error()))
		return
	}
	var n uint32
	if err := sysIoctl(master.Fd(), iocTIOCGPTN, uintptr(unsafe.Pointer(&n))); err != nil {
		master.Close()
		sendText(conn, ptyResult(id, "pty: TIOCGPTN failed: "+err.Error()))
		return
	}
	var unlocked uint32
	if err := sysIoctl(master.Fd(), iocTIOCSPTLCK, uintptr(unsafe.Pointer(&unlocked))); err != nil {
		master.Close()
		sendText(conn, ptyResult(id, "pty: TIOCSPTLCK failed: "+err.Error()))
		return
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR, 0)
	if err != nil {
		master.Close()
		sendText(conn, ptyResult(id, "pty: open slave failed: "+err.Error()))
		return
	}
	cols, rows := ptyTermSize(arg)
	var wsz struct{ Row, Col, X, Y uint16 }
	wsz.Row, wsz.Col = rows, cols
	sysIoctl(master.Fd(), iocSetWinsize, uintptr(unsafe.Pointer(&wsz)))

	cmd := exec.Command(currentShell(), "-i")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	sess := &ptySession{master: master, child: cmd, conn: conn}
	if err := cmd.Start(); err != nil {
		master.Close()
		slave.Close()
		sendText(conn, ptyResult(id, "pty: spawn failed: "+err.Error()))
		return
	}
	slave.Close()

	ptyMu.Lock()
	activePty = sess
	ptyMu.Unlock()
	sendText(conn, ptyResult(id, fmt.Sprintf(
		"pty up: /dev/pts/%d (%s -i, %dx%d) — type commands raw; .q returns to verbs",
		n, currentShell(), cols, rows)))

	go func() {
		buf := make([]byte, 8192)
		for {
			n2, rerr := master.Read(buf)
			if n2 > 0 {
				err := sendText(sess.conn, map[string]interface{}{
					"id":   0,
					"type": "pty_out",
					"data": base64.StdEncoding.EncodeToString(buf[:n2]),
				})
				if err != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		cmd.Wait()
		sess.kill()
		sendText(sess.conn, map[string]interface{}{"id": 0, "type": "pty_exit"})
	}()
}
