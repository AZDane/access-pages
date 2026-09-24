package main

import (
	"crypto/rand"
	"encoding/hex"
	"syscall"
	"time"
	"unsafe"
)

const actionLifetime = 8 * time.Second
const requestIDHeader = "X-Access-Pages-Request-ID"
const startedHeader = "X-Access-Pages-Started-Ns"

// CLOCK_BOOTTIME is shared with Python on this host and includes suspend.
func bootNanos() (int64, error) {
	var ts syscall.Timespec
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 7, uintptr(unsafe.Pointer(&ts)), 0)
	if errno != 0 {
		return 0, errno
	}
	return ts.Nano(), nil
}

func opaqueID() string {
	var value [16]byte
	_, _ = rand.Read(value[:]) // crypto/rand.Read cannot return an error on supported Go.
	return hex.EncodeToString(value[:])
}
