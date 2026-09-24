package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticTimestampCapturedBeforeQueueDelay(t *testing.T) {
	// Queue with no worker: no write can influence the observation timestamp.
	sink := &diagnosticSink{queue: make(chan diagnostic, 16)}
	before := time.Now().UTC().Truncate(time.Millisecond)
	sink.emit(diagnostic{At: "end", Outcome: "error"})
	after := time.Now().UTC()
	record := <-sink.queue
	observed, err := time.Parse("2006-01-02T15:04:05.000Z", record.Timestamp)
	if err != nil || len(record.Timestamp) != 24 || observed.Before(before) || observed.After(after) {
		t.Fatalf("invalid observation time: %+v (%v)", record, err)
	}
	// Retain the record while output is delayed, then use the real worker.
	time.Sleep(20 * time.Millisecond)
	lines := make(chan []byte, 1)
	writer := diagnosticWriteFunc(func(line []byte) (int, error) {
		lines <- append([]byte(nil), line...)
		return len(line), nil
	})
	sink.write = writer
	sink.queue <- record
	go sink.run()
	select {
	case line := <-lines:
		var persisted diagnostic
		if err := json.Unmarshal(line, &persisted); err != nil || persisted.Timestamp != record.Timestamp {
			t.Fatalf("queue delay changed timestamp: %s (%v)", line, err)
		}
	case <-time.After(time.Second):
		t.Fatal("diagnostic not emitted")
	}
}

type diagnosticWriteFunc func([]byte) (int, error)

func (f diagnosticWriteFunc) Write(line []byte) (int, error) { return f(line) }

func TestMaximumTimestampedDiagnosticFitsBound(t *testing.T) {
	record := diagnostic{Version: 1, Timestamp: diagnosticTimestamp(), PID: 2147483647,
		RequestID: strings.Repeat("f", 32), Part: "gateway", At: "end",
		Operation: "verification", ElapsedMS: diagnosticLimit, Status: 599,
		Outcome: "uncertain", Lost: lossLimit}
	for i := range 10 {
		record.Stages[i] = diagnosticLimit
	}
	record.Stages[10], record.Stages[11] = 2, 7
	line, err := json.Marshal(record)
	if err != nil || len(line)+1 > 512 {
		t.Fatalf("maximum record exceeds bound: %d (%v)", len(line)+1, err)
	}
}
