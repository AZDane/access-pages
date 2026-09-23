"""Compact observations of existing traffic, emitted only through App stderr."""
from contextlib import contextmanager
import json
import os
from queue import Empty, Full, Queue
import re
import sys
from threading import RLock, Thread

import guest_request as request

STAGES = "X-Access-Pages-Diagnostic-Stages"
# Millisecond offsets: service receipt, RPC start, broker start, HA start/end,
# broker ready, service ready; then HA count/total ms, RPC count, dispatch, failure.
LIMIT = 600_000
COUNTER_MAX = 2_147_483_647
try:
    DETAIL_UNTIL = int(os.getenv("ACCESS_PAGES_DIAGNOSTICS_UNTIL_NS", "0"))
except ValueError:
    DETAIL_UNTIL = 0
# The supervisor supplies an absolute BOOTTIME deadline, never a renewed duration.
DETAIL_UNTIL = min(DETAIL_UNTIL, request.clock_ns() + 14_400_000_000_000)


def detailed():
    return request.clock_ns() < DETAIL_UNTIL


class Budget:
    """Token bucket: normal burst 1 / 60 seconds; detailed burst 12 / 2 seconds."""
    def __init__(self):
        self.tokens = 0.0
        self.last = None
        self.mode = None

    def take(self, now, detail):
        capacity, interval = (12, 2_000_000_000) if detail else (1, 60_000_000_000)
        if self.mode != detail:
            self.tokens = float(capacity)
            self.mode = detail
        elif self.last is not None:
            self.tokens = min(capacity, self.tokens + max(0, now - self.last) / interval)
        self.last = now
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True


class DiagnosticSink:
    def __init__(self, write=None):
        self.queue = Queue(maxsize=16)
        self.write = write or sys.stderr.write
        self.lost = 0
        self.reported = 0
        self.lock = RLock()
        self.admission = Budget()
        self.output = Budget()
        self.worker = None

    def lose(self):
        with self.lock:
            self.lost = min(COUNTER_MAX, self.lost + 1)

    def emit(self, record, *, detail=False):
        # No output I/O, serialization or worker-held lock on the request path.
        with self.lock:
            if self.worker is None:
                self.worker = Thread(target=self._run, daemon=True)
                try:
                    self.worker.start()
                except RuntimeError:
                    self.worker = False
            if self.worker is False:
                self.lose()
                return
            if not self.admission.take(request.clock_ns(), detailed()):
                self.lose()
                return
            try:
                self.queue.put_nowait((record, detail))
            except Full:
                self.lose()

    def _write(self, record, detail=False):
        # Gate actual output too: a recovered blocked writer cannot drain a burst
        # accumulated across hours, or emit expired detailed records.
        if detail and not detailed():
            self.lose()
            return
        if not self.output.take(request.clock_ns(), detailed()):
            self.lose()
            return
        lost = self.lost
        line = json.dumps({"ap_diag": 1, "pid": os.getpid(), **record,
                           "lost": lost}, separators=(",", ":")) + "\n"
        if len(line.encode("ascii")) > 512:
            self.lose()
            return
        try:
            self.write(line)
            self.reported = lost
        except (OSError, ValueError):
            self.lose()

    def _run(self):
        while True:
            try:
                record, detail = self.queue.get(timeout=60)
            except Empty:
                if self.lost != self.reported:
                    self._write({"at": "loss"})
                continue
            try:
                self._write(record, detail)
            finally:
                self.queue.task_done()


SINK = DiagnosticSink()


def offset(timing):
    return min(LIMIT, max(0, (request.clock_ns() - timing.started_ns) // 1_000_000))


def boundary(index, component):
    timing = request.CURRENT.get()
    if timing is None or timing.operation == "asset":
        return
    if index != 1 or timing.stages[index] < 0:
        timing.stages[index] = offset(timing)
    if detailed():
        record(component, str(index), detail=True)


def failure(code):
    timing = request.CURRENT.get()
    if timing:
        timing.stages[11] = code


def record(component, at="end", status=0, *, detail=False):
    timing = request.CURRENT.get()
    if timing is None or timing.operation == "asset":
        return
    if component not in {"service", "broker", "ha"} or at not in {*map(str, range(7)), "end"}:
        return
    dispatch, fault = timing.stages[10:12]
    outcome = ("uncertain" if timing.action_deadline and dispatch in (0, 2) and (fault or status >= 500)
               else "deadline" if fault == 3 else "disconnect" if fault == 4
               else "error" if fault or status >= 500 else "slow" if offset(timing) >= 5000
               else "ok")
    SINK.emit({"id": timing.request_id, "part": component, "at": at,
               "op": timing.operation, "ms": offset(timing), "status": status or 0,
               "outcome": outcome, "v": tuple(timing.stages)}, detail=detail)


def stage_header():
    timing = request.CURRENT.get()
    return ",".join(map(str, timing.stages)) if timing and timing.operation != "asset" else ""


def receive_stages(value):
    timing = request.CURRENT.get()
    if timing is None or not isinstance(value, str) or len(value) > 96:
        return
    if not re.fullmatch(r"(?:-1|[0-9]{1,6})(?:,(?:-1|[0-9]{1,6})){11}", value):
        return
    values = [int(part) for part in value.split(",")]
    if (any(v > LIMIT for v in values) or any(v < 0 for v in values[7:])
            or values[10] > 3 or values[11] > 7):
        return
    for i in range(2, 7):
        if values[i] >= 0:
            # First start, latest completion; counts/totals describe repeated HA calls.
            timing.stages[i] = (values[i] if i not in (2, 3) or timing.stages[i] < 0
                                else min(timing.stages[i], values[i]))
    for i in (7, 8):
        timing.stages[i] = min(LIMIT, timing.stages[i] + values[i])
    timing.stages[10] = values[10]
    timing.stages[11] = max(timing.stages[11], values[11])


@contextmanager
def ha_request(service=False):
    timing = request.CURRENT.get()
    started = request.clock_ns()
    if timing:
        timing.stages[7] = min(LIMIT, timing.stages[7] + 1)
        if service:
            timing.stages[10] = 2  # Invocation attempted, not proof of delivery.
        if timing.stages[3] < 0:
            boundary(3, "ha")
        elif detailed():
            record("ha", "3", detail=True)
    try:
        yield
    except Exception:
        failure(1)
        raise
    else:
        if timing and service:
            timing.stages[10] = 3
    finally:
        if timing:
            timing.stages[8] = min(LIMIT, timing.stages[8] + max(0, (request.clock_ns() - started) // 1_000_000))
        boundary(4, "ha")
