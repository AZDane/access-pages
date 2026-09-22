"""Bounded, non-authorizing guest timing context on the local Linux host."""

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
import json
import os
from queue import Full, Queue
import re
import secrets
import sys
from threading import Thread
import time


ACTION_LIFETIME_NS = 8_000_000_000
REQUEST_ID = "X-Access-Pages-Request-ID"
STARTED_NS = "X-Access-Pages-Started-Ns"
RPC_STARTED_NS = "X-Access-Pages-Rpc-Started-Ns"
OPERATION = "X-Access-Pages-Operation"
STAGES = "X-Access-Pages-Diagnostic-Stages"
SLOW_NS = 250_000_000
QUEUE_NS = 100_000_000
STAGE_EVENTS = ("guest_service_received", "broker_rpc_sent", "broker_request_started",
                "ha_request_started", "ha_response_completed")
CURRENT = ContextVar("guest_request_timing", default=None)
EVENTS = frozenset({
    "guest_service_received", "guest_response_written", "broker_rpc_sent",
    "broker_request_started", "broker_response_written", "ha_request_started",
    "ha_response_completed", "action_not_dispatched",
    "guest_work_completed", "broker_rpc_failed", "guest_request_failed",
})
OPERATIONS = frozenset({
    "bootstrap", "document", "asset", "state", "camera", "verification", "action", "other",
})
OUTCOMES = frozenset({
    "started", "success", "denied", "unavailable", "disconnected", "timeout",
    "deadline_exceeded", "invalid", "error",
})


def clock_ns():
    # Same clock as the Go endpoint; includes suspend and ignores wall-clock jumps.
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


class ActionDeadlineExceeded(Exception):
    pass


@dataclass
class StateTrace:
    records: list = field(default_factory=list)
    stages: list = field(default_factory=lambda: [-1] * 6)
    interesting: bool = False
    dropped: int = field(default_factory=lambda: SINK.dropped)

    def flush(self):
        self.interesting = True
        for record in self.records:
            SINK.emit(record)
        self.records.clear()


@dataclass(frozen=True)
class RequestTiming:
    request_id: str
    started_ns: int
    operation: str
    rpc_started_ns: int = 0
    trace: StateTrace = field(default_factory=StateTrace, compare=False)
    action_deadline: bool = False

    def remaining(self):
        remaining = (self.started_ns + ACTION_LIFETIME_NS - clock_ns()) / 1e9
        if remaining <= 0:
            raise ActionDeadlineExceeded()
        return remaining

    def headers(self, rpc_started_ns):
        return (f"{REQUEST_ID}: {self.request_id}\r\n"
                f"{STARTED_NS}: {self.started_ns}\r\n"
                f"{OPERATION}: {self.operation}\r\n"
                f"{RPC_STARTED_NS}: {rpc_started_ns}\r\n")


def timing_from_headers(headers, operation, *, required=False, internal_rpc=False):
    action_deadline = operation == "action"
    values = [headers.get_all(name, []) for name in (REQUEST_ID, STARTED_NS, RPC_STARTED_NS)]
    if not any(values) and not required:
        return None
    if len(values[0]) != 1 or len(values[1]) != 1 or len(values[2]) > 1:
        raise ValueError("Invalid request timing")
    if internal_rpc:
        operations = headers.get_all(OPERATION, [])
        # The actual broker route owns action semantics, never diagnostic metadata.
        if operation != "action":
            operation = operations[0] if len(operations) == 1 and operations[0] in OPERATIONS else "other"
    request_id, started = values[0][0], values[1][0]
    rpc = values[2][0] if values[2] else "0"
    if (not re.fullmatch(r"[a-f0-9]{32}", request_id)
            or not re.fullmatch(r"[0-9]{1,19}", started)
            or not re.fullmatch(r"[0-9]{1,19}", rpc)
            or operation not in OPERATIONS):
        raise ValueError("Invalid request timing")
    started, rpc = int(started), int(rpc)
    now = clock_ns()
    if not 0 < started <= now or (rpc and not started <= rpc <= now):
        raise ValueError("Invalid request timing")
    return RequestTiming(request_id, started, operation, rpc, action_deadline=action_deadline)


def action_remaining(default):
    timing = CURRENT.get()
    return min(default, timing.remaining()) if timing and timing.action_deadline else default


def guest_operation(method, path, bootstrap=False):
    parts = path.split("/")
    if method == "GET" and (len(parts) == 3 and parts[1] == "static"
                            or len(parts) == 6 and parts[1] == "g" and parts[4] == "static"):
        return "asset"
    if len(parts) >= 5 and parts[1] == "g":
        if len(parts) == 5 and parts[4] == "":
            return "bootstrap" if bootstrap else "document"
        if method == "GET" and len(parts) == 7 and parts[4:6] == ["api", "access"]:
            return "state"
        if len(parts) == 9 and parts[4:6] == ["api", "access"]:
            if method == "GET" and parts[7] == "camera":
                return "camera"
            if method == "POST":
                # These two routes require payload validation to distinguish
                # verification from a saved action. The RPC supplies that context.
                if parts[7] == "verification" and parts[8] in {"send", "verify"}:
                    return "other"
                return "action"
    return "other"


class DiagnosticSink:
    def __init__(self, write=None, capacity=256):
        self.queue = Queue(maxsize=capacity)
        self.write = write or sys.stderr.write
        self.dropped = 0
        self.instance = secrets.token_hex(8)
        Thread(target=self._run, daemon=True).start()

    def emit(self, record):
        # Only the background worker performs JSON serialization or output I/O.
        try:
            self.queue.put_nowait({**record, "process_id": os.getpid(),
                                   "instance_id": self.instance,
                                   "dropped_events": self.dropped})
        except Full:
            self.dropped += 1

    def _run(self):
        while True:
            record = self.queue.get()
            try:
                self.write(json.dumps(record, separators=(",", ":")) + "\n")
            except (OSError, ValueError):
                self.dropped += 1
            finally:
                self.queue.task_done()


SINK = DiagnosticSink()


def stage_header():
    timing = CURRENT.get()
    if timing is None or timing.operation != "state":
        return ""
    return ",".join(str(value) for value in (*timing.trace.stages, int(timing.trace.interesting)))


def receive_stages(value):
    timing = CURRENT.get()
    if timing is None or timing.operation != "state" or not isinstance(value, str):
        return
    # Fixed numeric schema, bounded independently of peer input. No raw header is logged.
    if not re.fullmatch(r"(?:-1|[0-9]{1,9})(?:,(?:-1|[0-9]{1,9})){5},[01]", value):
        return
    values = [int(part) for part in value.split(",")]
    if any(value > 600_000_000 for value in values):
        return
    for index, value in enumerate(values[:6]):
        if value >= 0:
            timing.trace.stages[index] = value
    if values[-1]:
        timing.trace.flush()


def finish():
    timing = CURRENT.get()
    if timing and timing.operation == "state":
        if clock_ns() - timing.started_ns >= SLOW_NS or timing.trace.dropped != SINK.dropped:
            timing.trace.flush()
        timing.trace.records.clear()


def emit(event, component, *, status=None, outcome="started", duration_ns=None,
         broker_wait_ns=None, ha_operation=None, work=None):
    timing = CURRENT.get()
    if timing is None or timing.operation == "asset":
        return
    # No arbitrary fields, paths, header values, exception text, or payloads.
    if (event not in EVENTS or component not in {"guest_service", "ha_broker", "ha_client"}
            or outcome not in OUTCOMES):
        raise ValueError("Invalid diagnostic category")
    record = {
        "event": event, "component": component, "request_id": timing.request_id,
        "operation": timing.operation, "outcome": outcome,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "elapsed_ms": round(max(0, clock_ns() - timing.started_ns) / 1e6, 3),
    }
    if type(status) is int and 100 <= status <= 599:
        record.update(status=status, status_class=f"{status // 100}xx")
    for name, value in (("duration_ms", duration_ns), ("broker_wait_ms", broker_wait_ns)):
        if value is not None:
            record[name] = round(max(0, value) / 1e6, 3)
    if ha_operation in {"state_read", "service_call", "camera_read", "other"}:
        record["ha_operation"] = ha_operation
    if work in {"connector_health", "session_validation", "policy_preparation", "guest_event"}:
        record["work"] = work
    if timing.operation == "state":
        trace = timing.trace
        if event in STAGE_EVENTS:
            trace.stages[STAGE_EVENTS.index(event)] = round(record["elapsed_ms"] * 1000)
        if broker_wait_ns is not None:
            trace.stages[5] = max(0, broker_wait_ns // 1000)
        if (record["elapsed_ms"] >= SLOW_NS / 1e6 or (broker_wait_ns or 0) >= QUEUE_NS
                or outcome not in {"started", "success"} or (status and status >= 400)
                or trace.dropped != SINK.dropped or len(trace.records) >= 32):
            trace.flush()
        if not trace.interesting:
            trace.records.append(record)
            return
    SINK.emit(record)


def error_outcome(error):
    if isinstance(error, ActionDeadlineExceeded):
        return "deadline_exceeded"
    if isinstance(error, (BrokenPipeError, ConnectionResetError)):
        return "disconnected"
    if isinstance(error, TimeoutError) or isinstance(getattr(error, "reason", None), TimeoutError):
        return "timeout"
    return "error"


def timed_work(component, work):
    """Measure local work without capturing arguments, return values or errors."""
    def decorate(function):
        @wraps(function)
        def measured(*args, **kwargs):
            if CURRENT.get() is None:
                return function(*args, **kwargs)
            started = clock_ns()
            outcome = "success"
            try:
                return function(*args, **kwargs)
            except Exception as error:
                outcome = error_outcome(error)
                raise
            finally:
                emit("guest_work_completed", component, work=work, outcome=outcome,
                     duration_ns=clock_ns() - started)
        return measured
    return decorate


@contextmanager
def ha_request(operation):
    result = {}
    if CURRENT.get() is None:
        yield result
        return
    started = clock_ns()
    emit("ha_request_started", "ha_client", ha_operation=operation)
    try:
        yield result
    except Exception as error:
        emit("ha_response_completed", "ha_client", ha_operation=operation,
             outcome=error_outcome(error), status=getattr(error, "code", None),
             duration_ns=clock_ns() - started)
        raise
    else:
        emit("ha_response_completed", "ha_client", ha_operation=operation,
             outcome="success", status=result.get("status"), duration_ns=clock_ns() - started)
