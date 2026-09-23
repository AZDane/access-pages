"""Trusted request lifetime and fixed boundary context; no logging dependencies."""
from contextvars import ContextVar
from dataclasses import dataclass, field
import re
import time

ACTION_LIFETIME_NS = 8_000_000_000
REQUEST_ID = "X-Access-Pages-Request-ID"
STARTED_NS = "X-Access-Pages-Started-Ns"
RPC_STARTED_NS = "X-Access-Pages-Rpc-Started-Ns"
OPERATION = "X-Access-Pages-Operation"
CURRENT = ContextVar("guest_request", default=None)
OPERATIONS = frozenset({"bootstrap", "document", "asset", "state", "camera",
                        "verification", "action", "other"})

def clock_ns():
    # Same clock as the Go endpoint; includes suspend and ignores wall-clock jumps.
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME)


class ActionDeadlineExceeded(Exception):
    pass


@dataclass(slots=True)
class RequestTiming:
    request_id: str
    started_ns: int
    operation: str
    rpc_started_ns: int = 0
    stages: list = field(default_factory=lambda: [-1] * 7 + [0, 0, 0, 1, 0])
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


