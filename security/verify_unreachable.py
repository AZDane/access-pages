"""Reproduce bounded reachability assessments inside the shipped image.

This prints evidence; it does not approve a finding. The baseline checks the
exact binary and source hashes, architecture, advisory fingerprint and dates.
"""

import ast
from hashlib import sha256
import json
from pathlib import Path
import platform
import re
import sqlite3
import struct


SQL_FILES = (
    "activity.py", "verification.py", "guest_resources.py",
    "upstream_cleanup.py", "layerv_broker.py", "schedules.py",
)


def go_functions(binary):
    if binary[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Expected a little-endian ELF64 qURL binary")
    offset = struct.unpack_from("<Q", binary, 40)[0]
    size, count, strings = struct.unpack_from("<HHH", binary, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", binary, offset + i * size)
                for i in range(count)]
    section = sections[strings]
    names = binary[section[4]:section[4] + section[5]]
    matches = [s for s in sections if names[s[0]:].split(b"\0")[0] == b".gopclntab"]
    if len(matches) != 1:
        raise ValueError("Missing Go function table; reassessment required")
    section = matches[0]
    table = binary[section[4]:section[4] + section[5]]
    start, end = struct.unpack_from("<QQ", table, 32)
    if not 0 < start < end <= len(table):
        raise ValueError("Unexpected Go function table layout")
    functions = [name.decode("utf-8") for name in table[start:end].split(b"\0") if name]
    if len(functions) < 1000:
        raise ValueError("Incomplete Go function table")
    return functions


def sqlite_schema_evidence(root):
    total = 0
    schemas = {}
    for filename in SQL_FILES:
        tree = ast.parse((root / filename).read_text())
        with sqlite3.connect(":memory:") as db:
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                    continue
                if node.func.attr in {"load_extension", "enable_load_extension", "deserialize"}:
                    raise ValueError("SQLite extension/deserialization use requires review")
                if node.func.attr not in {"execute", "executemany", "executescript"}:
                    continue
                if not node.args or not isinstance(node.args[0], ast.Constant):
                    raise ValueError(f"Nonconstant SQL in {filename}:{node.lineno}")
                sql = node.args[0].value
                if not isinstance(sql, str) or re.search(r"\b(fts[345]|match|virtual|load_extension)\b", sql, re.I):
                    raise ValueError(f"Unreviewed SQL in {filename}:{node.lineno}")
                total += 1
                if sql.lstrip().upper().startswith("CREATE"):
                    db.executescript(sql)
            schemas[filename] = db.execute(
                "SELECT type,name,sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY type,name"
            ).fetchall()
    if total != 147 or any(not schema for schema in schemas.values()):
        raise ValueError("SQLite consumers/schema changed; reassessment required")
    return {"sql_calls": total, "schemas": schemas}


def html_parser_evidence(functions):
    # Inspect the parsed ELF function table, including wrapper/type symbols.
    html = sorted(name for name in functions if "golang.org/x/net/html" in name)
    if html:
        raise ValueError("x/net/html code is linked; reassess CVE-2026-78661")
    return html


def sqlite_session_evidence(root):
    # The stdlib binding has no session/changeset API. Fail if that changes,
    # or if packaged application code starts using a native-library bridge.
    api = sorted(name for obj in (sqlite3, sqlite3.Connection) for name in dir(obj)
                 if "session" in name.lower() or "changeset" in name.lower())
    if api:
        raise ValueError("SQLite session API exposed; reassessment required")
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            modules = ([a.name for a in node.names] if isinstance(node, ast.Import)
                       else [node.module or ""] if isinstance(node, ast.ImportFrom) else [])
            if any(m.split(".")[0] in {"ctypes", "cffi", "apsw"} for m in modules):
                raise ValueError("Native SQLite bridge requires review")
    return api


def collect(root=Path("/app")):
    binary = Path("/usr/local/bin/qurl").read_bytes()
    functions = go_functions(binary)
    jose = sorted(name for name in functions if "go-jose" in name or "go-oidc" in name)
    allowed = ("github.com/go-jose/go-jose/v4/json.",
               "type:.eq.github.com/go-jose/go-jose/v4/json.")
    if not jose or any(not (name.startswith(allowed) or name in {
        "github.com/go-jose/go-jose/v4.init", "github.com/coreos/go-oidc/v3/oidc.init",
    }) for name in jose):
        raise ValueError("JOSE/OIDC parser or other unreviewed code is linked")
    libraries = list(Path("/usr/lib").glob("*/libsqlite3.so.0.*"))
    if len(libraries) != 1:
        raise ValueError("Unexpected SQLite libraries")
    files = {p.name: "sha256:" + sha256(p.read_bytes()).hexdigest() for p in root.glob("*.py")}
    files["homeassistant-app/app_runner.py"] = "sha256:" + sha256(
        Path("/usr/local/bin/app_runner.py").read_bytes()
    ).hexdigest()
    return {
        "architecture": {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()],
        "files": files,
        "qurl_sha256": sha256(binary).hexdigest(),
        "jose_functions": jose,
        "html_functions": html_parser_evidence(functions),
        "sqlite_sha256": sha256(libraries[0].read_bytes()).hexdigest(),
        "sqlite_version": sqlite3.sqlite_version,
        "sqlite_schema": sqlite_schema_evidence(root),
        "sqlite_session_bindings": sqlite_session_evidence(root),
    }


if __name__ == "__main__":
    print(json.dumps(collect(), sort_keys=True))
