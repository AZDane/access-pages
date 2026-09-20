"""One-time, Ingress-only LayerV credential onboarding."""

from __future__ import annotations

from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from threading import Event, Lock


HOST = os.environ.get("ONBOARDING_HOST", "127.0.0.1")
PORT = int(os.environ.get("ONBOARDING_PORT", "8080"))
SUBMISSION_FD = int(os.environ.get("ONBOARDING_SUBMISSION_FD", "-1"))
ACK_FD = int(os.environ.get("ONBOARDING_ACK_FD", "-1"))
SETUP_ERROR = os.environ.get("ONBOARDING_ERROR", "").strip()
MAX_BODY_BYTES = 16_384

HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Access Pages — Connect to LayerV</title>
  <link rel="stylesheet" href="onboarding.css">
</head>
<body>
  <main>
    <div class="brand">Access Pages</div>
    <section class="card">
      <p class="eyebrow">SECURE SETUP</p>
      <h1>Connect to LayerV</h1>
      <p>Access Pages uses LayerV to provide protected guest access. Enter a
         dedicated LayerV API key for this Home Assistant installation.
         It is passed to the App's protected credential writer and is never
         saved in Home Assistant App options.</p>
      <div id="setup-error" class="error"></div>
      <form id="connect-form">
        <label for="api-key">LayerV API key</label>
        <input id="api-key" name="api-key" type="password"
               autocomplete="off" spellcheck="false" required>
        <p class="help">Recommended scopes: Read qURLs; Create, update &amp;
           delete qURLs; Bootstrap LayerV qURL Connector agents.</p>
        <button type="submit">Connect LayerV</button>
      </form>
      <p id="status" role="status"></p>
    </section>
    <p class="provider">Powered by <a href="https://layerv.ai" target="_blank"
       rel="noopener noreferrer">LayerV</a></p>
  </main>
  <script src="onboarding.js"></script>
</body>
</html>
"""

CSS = """
:root { color-scheme: dark; font-family: Inter, system-ui, sans-serif; }
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; color: #eef5ff;
  background: radial-gradient(circle at 80% 20%, #27166e, transparent 34%),
              linear-gradient(145deg, #06182b, #0c1940 60%, #171052); }
main { width: min(720px, calc(100% - 32px)); margin: 0 auto; padding: 52px 0; }
.brand { color: #fff; font-size: 34px;
  font-weight: 800; margin-bottom: 28px; }
.brand::before { content: "◆"; color: #18c8e8; margin-right: 12px; }
.card { padding: clamp(24px, 5vw, 48px); border: 1px solid #315079;
  border-radius: 28px; background: rgba(8, 25, 51, .92);
  box-shadow: 0 26px 70px rgba(0, 0, 0, .34); }
.provider { margin: 20px 0 0; text-align: center; font-size: 14px; }
.provider a { color: #eef5ff; }
.eyebrow { color: #1cc8e8; font-weight: 800; letter-spacing: .15em; }
h1 { margin: 8px 0 18px; font-size: clamp(34px, 7vw, 56px); }
p { color: #b8c8df; line-height: 1.6; }
label { display: block; margin: 28px 0 10px; font-weight: 750; }
input { width: 100%; min-height: 58px; padding: 12px 16px; color: #fff;
  background: #09172d; border: 1px solid #345174; border-radius: 14px;
  font: inherit; }
input:focus { outline: 3px solid rgba(25, 198, 232, .28);
  border-color: #19c6e8; }
.help { font-size: 14px; }
button { min-height: 54px; margin-top: 14px; padding: 0 24px; border: 0;
  border-radius: 14px; color: #fff; font: inherit; font-weight: 800;
  cursor: pointer; background: linear-gradient(110deg, #16c9e8, #8144f5); }
button:disabled { cursor: wait; opacity: .65; }
.error { display: none; margin-top: 18px; padding: 14px; border-radius: 12px;
  color: #ffd5dc; background: rgba(174, 37, 68, .25); }
.error.visible { display: block; }
#status { min-height: 24px; color: #7ce8c1; }
"""

JAVASCRIPT = """
const form = document.getElementById("connect-form");
const input = document.getElementById("api-key");
const status = document.getElementById("status");
const errorBox = document.getElementById("setup-error");
const configuredError = document.documentElement.dataset.setupError || "";
if (configuredError) {
  errorBox.textContent = configuredError;
  errorBox.classList.add("visible");
}
async function waitForGateway(timeoutMs = 60000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(
        `health?transition=${Date.now()}`,
        {cache: "no-store"},
      );
      const result = await response.json();
      if (response.ok && result.status === "ok") return true;
    } catch (_error) {
      // Registration briefly leaves the proxy without an upstream.
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return false;
}
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = form.querySelector("button");
  button.disabled = true;
  status.textContent = "Saving the credential securely…";
  errorBox.classList.remove("visible");
  try {
    const response = await fetch("api/onboarding/key", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({api_key: input.value}),
    });
    const contentType = response.headers.get("Content-Type") || "";
    let result;
    try {
      if (!contentType.toLowerCase().startsWith("application/json")) {
        throw new Error("Non-JSON response");
      }
      result = await response.json();
    } catch (_error) {
      throw new Error(
        "Setup response was interrupted. Reopen the Gateway to check status.",
      );
    }
    if (!response.ok) throw new Error(result.error || "Setup failed");
    if (result.success !== true) throw new Error("Setup response was invalid");
    input.value = "";
    status.textContent = "Credential saved. LayerV is connecting…";
    if (await waitForGateway()) {
      window.location.reload();
    } else {
      status.textContent =
        "LayerV is taking longer than expected. Reopen the Gateway from " +
        "the Home Assistant sidebar.";
      button.disabled = false;
    }
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.classList.add("visible");
    status.textContent = "";
    button.disabled = false;
  }
});
"""


def _submit_secret(value: str) -> None:
    if SUBMISSION_FD < 0 or ACK_FD < 0:
        raise RuntimeError("Credential handoff is unavailable")
    payload = (value + "\n").encode("utf-8")
    written = 0
    while written < len(payload):
        count = os.write(SUBMISSION_FD, payload[written:])
        if count <= 0:
            raise RuntimeError("Credential handoff failed")
        written += count
    if os.read(ACK_FD, 1) != b"1":
        raise RuntimeError("Credential persistence failed")


def _valid_key(value: object) -> str:
    key = str(value or "").strip()
    if len(key) < 10 or len(key) > 4096:
        raise ValueError("Enter a valid LayerV API key")
    if any(character.isspace() for character in key):
        raise ValueError("The LayerV API key cannot contain spaces")
    return key


class Handler(BaseHTTPRequestHandler):
    server_version = "AccessPagesOnboarding/1"

    def log_message(self, _format, *_args):
        # Request paths are fixed and credential bodies must never be logged.
        return

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; script-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none';",
        )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: dict) -> None:
        self._send(
            status,
            json.dumps(payload).encode("utf-8"),
            "application/json; charset=utf-8",
        )

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in {"/", "/admin"}:
            document = HTML.replace(
                "<html lang=\"en\">",
                (
                    '<html lang="en" data-setup-error="'
                    + SETUP_ERROR.replace("&", "&amp;")
                    .replace('"', "&quot;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    + '">'
                ),
            )
            self._send(200, document.encode("utf-8"), "text/html; charset=utf-8")
        elif path.endswith("/onboarding.css"):
            self._send(200, CSS.encode("utf-8"), "text/css; charset=utf-8")
        elif path.endswith("/onboarding.js"):
            self._send(
                200,
                JAVASCRIPT.encode("utf-8"),
                "text/javascript; charset=utf-8",
            )
        elif path.endswith("/health"):
            self._json(200, {"status": "setup_required"})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        if not self.path.split("?", 1)[0].endswith("/api/onboarding/key"):
            self._json(404, {"error": "not found"})
            return
        with self.server.submission_lock:
            if self.server.completed.is_set():
                self._json(
                    HTTPStatus.CONFLICT,
                    {"error": "A LayerV API key was already submitted"},
                )
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > MAX_BODY_BYTES:
                    raise ValueError("Invalid request size")
                payload = json.loads(self.rfile.read(length).decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("Request must be a JSON object")
                key = _valid_key(payload.get("api_key"))
                _submit_secret(key)
            except (
                ValueError,
                UnicodeDecodeError,
                json.JSONDecodeError,
            ) as error:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
                return
            except (OSError, RuntimeError):
                try:
                    self._json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {"error": "Could not store the LayerV API key"},
                    )
                finally:
                    self.server.completed.set()
                return
            try:
                self._json(HTTPStatus.CREATED, {"success": True})
            finally:
                # The server may exit only after the request thread finishes
                # writing the entire response to the proxy.
                self.server.completed.set()


def main() -> int:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.timeout = 0.5
    server.completed = Event()
    server.submission_lock = Lock()
    while not server.completed.is_set():
        server.handle_request()
    server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
