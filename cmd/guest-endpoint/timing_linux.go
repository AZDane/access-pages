package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// A closed App log pipe must report EPIPE to the worker, not kill the Gateway.
func init() { signal.Ignore(syscall.SIGPIPE) }

const stagesHeader = "X-Access-Pages-Diagnostic-Stages"
const diagnosticLimit = 600_000
const lossLimit = 2_147_483_647

type requestTraceKey struct{}
type requestTrace struct{ stages [12]int64 }

func newRequestTrace() *requestTrace {
	t := &requestTrace{}
	for i := range 7 {
		t.stages[i] = -1
	}
	t.stages[10] = 0 // Dispatch unknown until a trusted backend reports otherwise.
	return t
}

func captureDiagnosticStages(response *http.Response) error {
	values := response.Header.Values(stagesHeader)
	response.Header.Del(stagesHeader)
	trace, ok := response.Request.Context().Value(requestTraceKey{}).(*requestTrace)
	if !ok || len(values) != 1 || len(values[0]) > 96 {
		return nil
	}
	parts := strings.Split(values[0], ",")
	if len(parts) != 12 {
		return nil
	}
	var stages [12]int64
	for i := range stages {
		value, err := strconv.ParseInt(parts[i], 10, 64)
		if err != nil || value < -1 || value > diagnosticLimit || (i >= 7 && value < 0) {
			return nil
		}
		stages[i] = value
	}
	if stages[10] > 3 || stages[11] > 7 {
		return nil
	}
	trace.stages = stages
	return nil // Malformed observations never reject a valid response.
}

type diagnostic struct {
	Version   int       `json:"ap_diag"`
	PID       int       `json:"pid"`
	RequestID string    `json:"id,omitempty"`
	Part      string    `json:"part"`
	At        string    `json:"at"`
	Operation string    `json:"op,omitempty"`
	ElapsedMS int64     `json:"ms"`
	Status    int       `json:"status,omitempty"`
	Outcome   string    `json:"outcome,omitempty"`
	Stages    [12]int64 `json:"v"`
	Lost      uint64    `json:"lost"`
	detail    bool
}

var detailUntil = func() int64 {
	until, _ := strconv.ParseInt(os.Getenv("ACCESS_PAGES_DIAGNOSTICS_UNTIL_NS"), 10, 64)
	now, _ := bootNanos()
	return min(until, now+int64(4*time.Hour))
}()

func detailedAt(now int64) bool { return now > 0 && now < detailUntil }

type diagnosticBudget struct {
	tokens      float64
	last        int64
	mode        bool
	initialized bool
}

func (b *diagnosticBudget) take(now int64, detail bool) bool {
	capacity, interval := 1.0, float64(time.Minute)
	if detail {
		capacity, interval = 12, float64(2*time.Second)
	}
	if !b.initialized || b.mode != detail {
		b.tokens = capacity
		b.initialized = true
	} else {
		b.tokens = min(capacity, b.tokens+float64(max(0, now-b.last))/interval)
	}
	b.mode, b.last = detail, now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type diagnosticSink struct {
	queue     chan diagnostic
	lost      atomic.Uint64
	lock      sync.Mutex
	admission diagnosticBudget
	output    diagnosticBudget
	write     io.Writer
}

func newDiagnosticSink(write io.Writer) *diagnosticSink {
	s := &diagnosticSink{queue: make(chan diagnostic, 16), write: write}
	go s.run()
	return s
}
func (s *diagnosticSink) lose() {
	for {
		old := s.lost.Load()
		if old >= lossLimit || s.lost.CompareAndSwap(old, old+1) {
			return
		}
	}
}
func (s *diagnosticSink) emit(record diagnostic) {
	now, _ := bootNanos()
	s.lock.Lock()
	defer s.lock.Unlock()
	if !s.admission.take(now, detailedAt(now)) {
		s.lose()
		return
	}
	select {
	case s.queue <- record:
	default:
		s.lose()
	}
}
func (s *diagnosticSink) run() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	var reported uint64
	for {
		var record diagnostic
		select {
		case record = <-s.queue:
		case <-ticker.C:
			if s.lost.Load() == reported {
				continue
			}
			record.At = "loss"
		}
		now, _ := bootNanos()
		if (record.detail && !detailedAt(now)) || !s.output.take(now, detailedAt(now)) {
			s.lose()
			continue
		}
		record.Version, record.PID, record.Part, record.Lost = 1, os.Getpid(), "gateway", s.lost.Load()
		line, err := json.Marshal(record)
		if err != nil || len(line)+1 > 512 {
			s.lose()
			continue
		}
		line = append(line, '\n')
		if n, err := s.write.Write(line); err != nil || n != len(line) {
			s.lose()
		} else {
			reported = record.Lost
		}
		s.output.last, _ = bootNanos() // Blocked time earns no output burst.
	}
}

var diagnostics = newDiagnosticSink(os.Stderr)

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
