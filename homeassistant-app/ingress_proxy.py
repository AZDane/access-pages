"""Private Home Assistant Ingress proxy that supplies gateway admin auth."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html import escape
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


UPSTREAM = os.environ.get("INGRESS_UPSTREAM", "http://127.0.0.1:8080").rstrip("/")
ADMIN_TOKEN = os.environ["INGRESS_ADMIN_TOKEN"]
PORT = int(os.environ.get("INGRESS_PORT", "8099"))
TRUSTED_INGRESS_PROXIES = frozenset(
    value.strip()
    for value in os.environ.get(
        "TRUSTED_INGRESS_PROXIES",
        "172.30.32.2",
    ).split(",")
    if value.strip()
)
MAX_BODY_BYTES = 512_000
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}


def _upstream_path(path: str) -> str:
    """Open the admin shell when Home Assistant requests the Ingress root."""
    parsed = urlsplit(path)
    if parsed.path != "/":
        return path
    return "/admin" + (f"?{parsed.query}" if parsed.query else "")


def _ingress_csp(value: str) -> str:
    """Allow only the same Home Assistant origin to frame Ingress content."""
    directives = [
        directive.strip()
        for directive in value.split(";")
        if directive.strip()
    ]
    directives = [
        directive
        for directive in directives
        if not directive.lower().startswith("frame-ancestors ")
    ]
    directives.append("frame-ancestors 'self'")
    return "; ".join(directives) + ";"


def _trusted_ingress_request(client_ip: str, ingress_path: str) -> bool:
    """Accept only requests delivered by Home Assistant Ingress."""
    return (
        client_ip in TRUSTED_INGRESS_PROXIES
        and ingress_path.startswith("/api/hassio_ingress/")
        and "\r" not in ingress_path
        and "\n" not in ingress_path
    )


def _inject_ingress_base(
    payload: bytes,
    content_type: str,
    ingress_path: str,
) -> bytes:
    """Resolve browser requests through Home Assistant's Ingress prefix."""
    if "text/html" not in content_type.lower():
        return payload
    if (
        not ingress_path.startswith("/")
        or "\r" in ingress_path
        or "\n" in ingress_path
    ):
        return payload

    base_path = ingress_path.rstrip("/") + "/"
    base = f'<base href="{escape(base_path, quote=True)}">'
    try:
        html = payload.decode("utf-8")
    except UnicodeDecodeError:
        return payload
    if "<base " in html.lower() or "<head>" not in html.lower():
        return payload
    html = html.replace('href="/static/', 'href="static/')
    html = html.replace('src="/static/', 'src="static/')
    return html.replace("<head>", f"<head>\n  {base}", 1).encode("utf-8")


def _transition_payload() -> bytes:
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta http-equiv=\"refresh\" content=\"2\"></head>"
        "<body><p>Access Pages is transitioning. Retrying shortly…</p>"
        "</body></html>"
    ).encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Ingress paths and query strings can carry authentication material.
        return

    def _proxy(self):
        ingress_path = self.headers.get("X-Ingress-Path", "")
        if not _trusted_ingress_request(
            self.client_address[0],
            ingress_path,
        ):
            self.send_error(403)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self.send_error(413)
            return
        body = self.rfile.read(length) if length else None
        headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP
            and key.lower() not in {"host", "content-length", "x-admin-token"}
        }
        headers["X-Admin-Token"] = ADMIN_TOKEN
        request = Request(
            f"{UPSTREAM}{_upstream_path(self.path)}",
            data=body,
            method=self.command,
            headers=headers,
        )
        try:
            # UPSTREAM is a fixed loopback URL, never browser-controlled.
            # Invitation creation can include cold native Connector enrollment.
            # Its private broker waits up to 360 seconds; this outer deadline
            # must leave time for the Gateway to return its result or error.
            invitation_create = self.command == "POST" and re.fullmatch(
                r"/api/admin/pages/[a-z0-9][a-z0-9_-]{0,63}/qurls",
                _upstream_path(self.path),
            )
            response = urlopen(request, timeout=390 if invitation_create else 30)  # nosec B310
        except HTTPError as error:
            response = error
        except URLError:
            # The supervised upstream is briefly absent while onboarding and
            # the gateway exchange port 8081. This is an expected local-only
            # transition, not an exception worth logging with a traceback.
            payload = _transition_payload()
            self.send_response(503)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Retry-After", "2")
            self.send_header(
                "Content-Security-Policy", "frame-ancestors 'self';"
            )
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        with response:
            payload = response.read()
            content_type = response.headers.get("Content-Type", "")
            payload = _inject_ingress_base(
                payload,
                content_type,
                ingress_path,
            )
            self.send_response(response.status)
            content_security_policy = None
            for key, value in response.headers.items():
                lower_key = key.lower()
                if lower_key == "content-security-policy":
                    content_security_policy = _ingress_csp(value)
                elif lower_key not in HOP_BY_HOP | {"content-length"}:
                    self.send_header(key, value)
            self.send_header(
                "Content-Security-Policy",
                content_security_policy or "frame-ancestors 'self';",
            )
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    do_DELETE = _proxy
    do_GET = _proxy
    do_POST = _proxy
    do_PUT = _proxy


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
