package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const actionLifetime = 8 * time.Second
const requestIDHeader = "X-Access-Pages-Request-ID"
const startedHeader = "X-Access-Pages-Started-Ns"
const stagesHeader = "X-Access-Pages-Diagnostic-Stages"

type stateTraceKey struct{}
type stateTrace struct {
	stages      []int64
	interesting bool
}

func captureDiagnosticStages(response *http.Response) error {
	values := response.Header.Values(stagesHeader)
	response.Header.Del(stagesHeader) // Internal timing is never a browser-facing header.
	trace, ok := response.Request.Context().Value(stateTraceKey{}).(*stateTrace)
	if !ok || len(values) != 1 || len(values[0]) > 80 {
		return nil
	}
	parts := strings.Split(values[0], ",")
	if len(parts) != 7 || (parts[6] != "0" && parts[6] != "1") {
		return nil
	}
	stages := make([]int64, 6)
	for i := range stages {
		value, err := strconv.ParseInt(parts[i], 10, 64)
		if err != nil || value < -1 || value > 600_000_000 {
			return nil // Telemetry cannot reject an otherwise valid response.
		}
		stages[i] = value
	}
	trace.stages, trace.interesting = stages, parts[6] == "1"
	return nil
}

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
	StagesUS    []int64 `json:"stages_us,omitempty"`
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
	if record.Timestamp == "" {
		record.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
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
