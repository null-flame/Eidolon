//go:build !wraithEmbedded

package main

// Defaults when built without the wraithEmbedded tag (manual `go build`).
const embedURL = "ws://127.0.0.1:8443/ws"
const embedToken = ""
