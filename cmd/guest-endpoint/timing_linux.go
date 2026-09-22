package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"sync/atomic"
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

type diagnostic struct {
	Event       string  `json:"event"`
	Component   string  `json:"component"`
	Instance    string  `json:"instance_id"`
	PID         int     `json:"process_id"`
	RequestID   string  `json:"request_id"`
	Operation   string  `json:"operation"`
	Timestamp   string  `json:"timestamp"`
	ElapsedMS   float64 `json:"elapsed_ms"`
	Status      int     `json:"status,omitempty"`
	StatusClass string  `json:"status_class,omitempty"`
	Outcome     string  `json:"outcome"`
	Bytes       int64   `json:"bytes,omitempty"`
	Dropped     uint64  `json:"dropped_events"`
}

var diagnosticQueue = make(chan diagnostic, 256)
var droppedDiagnostics atomic.Uint64
var diagnosticInstance = opaqueID()

func init() {
	go func() {
		encoder := json.NewEncoder(os.Stderr)
		for record := range diagnosticQueue {
			if encoder.Encode(record) != nil {
				droppedDiagnostics.Add(1)
			}
		}
	}()
}

func emitDiagnostic(record diagnostic) {
	record.Component, record.Instance, record.PID = "gateway", diagnosticInstance, os.Getpid()
	record.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	record.Dropped = droppedDiagnostics.Load()
	select {
	case diagnosticQueue <- record:
	default:
		droppedDiagnostics.Add(1)
	}
}

type observedResponse struct {
	http.ResponseWriter
	status int
	bytes  int64
	failed bool
}

func (w *observedResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *observedResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *observedResponse) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(body)
	w.bytes += int64(n)
	w.failed = w.failed || err != nil
	return n, err
}
