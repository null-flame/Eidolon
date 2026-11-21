//go:build !linux

package main

import (
	"errors"
	"net"
)

func ptyOpen(id int64, arg string, conn net.Conn) {
	_ = arg
	sendText(conn, ptyResult(id, "pty: interactive shell needs a linux implant — use `shell`"))
}

func ptySetSize(arg string) error {
	_ = arg
	return errors.New("pty: not supported on this platform")
}
