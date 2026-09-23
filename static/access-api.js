export class AccessConnectionError extends Error {}

async function boundedRequest(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  let requestId = null;
  try {
    const response = await window.fetch(url, {
      ...options,
      credentials: "same-origin",
      redirect: "error",
      signal: controller.signal,
    });
    const returnedId = response.headers.get("X-Access-Pages-Request-ID");
    if (/^[a-f0-9]{32}$/.test(returnedId || "")) requestId = returnedId;
    // Keep the deadline active through the body, not just response headers.
    const body = await response.arrayBuffer();
    return new Response(body.byteLength ? body : null, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  } catch {
    const error = new AccessConnectionError(controller.signal.aborted
      ? "Connection timed out. Check refreshed state before retrying a control."
      : "Connection unavailable. Waiting to reconnect.");
    error.requestId = requestId;
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function authorizationQuery(location) {
  const source = new URLSearchParams(location.search);
  const result = new URLSearchParams();

  if (source.get("preview_token")) {
    result.set("preview_token", source.get("preview_token"));
  }

  const encoded = result.toString();
  return encoded ? `?${encoded}` : "";
}

export function createAccessApi(location = window.location) {
  const preview = new URLSearchParams(location.search).has("preview_token");
  const prefix = preview
    ? (document.querySelector("base") ? "api/admin/preview" : "/api/admin/preview")
    : "api/access";

  function path(pageId, suffix = "") {
    return `${prefix}/${encodeURIComponent(pageId)}${suffix}`;
  }

  function authorizedPath(pageId, suffix = "") {
    return path(pageId, suffix) + authorizationQuery(location);
  }

  return Object.freeze({
    cameraFrame(pageId, resourceId, frame) {
      return boundedRequest(this.cameraUrl(pageId, resourceId, frame), {cache: "no-store"});
    },
    cameraUrl(pageId, resourceId, frame) {
      const target = authorizedPath(
        pageId,
        `/camera/${encodeURIComponent(resourceId)}`,
      );
      const separator = target.includes("?") ? "&" : "?";
      return `${target}${separator}frame=${frame}`;
    },
    fetchPage(pageId) {
      return boundedRequest(authorizedPath(pageId), {cache: "no-store"});
    },
    runAction(pageId, resourceId, actionId, payload) {
      return boundedRequest(
        authorizedPath(
          pageId,
          `/${encodeURIComponent(resourceId)}/${encodeURIComponent(actionId)}`,
        ),
        {
          method: "POST",
          headers: {"Content-Type": "application/json", "X-Guest-Request": "1"},
          body: JSON.stringify(payload),
        },
      );
    },
    verification(pageId, action, payload) {
      return boundedRequest(
        authorizedPath(pageId, `/verification/${action}`),
        {
          method: "POST",
          headers: {"Content-Type": "application/json", "X-Guest-Request": "1"},
          body: JSON.stringify(payload),
        },
      );
    },
  });
}
