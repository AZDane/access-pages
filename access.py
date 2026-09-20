"""Administrative page preview data and action routes."""


def handle_get(handler, path, runtime):
    remainder = path.removeprefix("/api/admin/preview/").strip("/")
    parts = remainder.split("/")
    if len(parts) == 3 and parts[1] == "camera":
        page = handler._load_page(parts[0])
        if page is not None and handler._require_preview_access(page):
            handler._send_camera_image(page, parts[2])
        return
    if len(parts) != 1 or not parts[0]:
        handler._send_json(404, {"error": "not found"})
        return
    page = handler._load_page(parts[0])
    if page is None or not handler._require_preview_access(page):
        return
    try:
        handler._send_json(200, handler._public_page(page))
    except runtime.HomeAssistantError as error:
        handler._send_ha_error(error)


def handle_post(handler, path, payload, runtime):
    parts = path.removeprefix("/api/admin/preview/").strip("/").split("/")
    if len(parts) != 3:
        handler._send_json(404, {"error": "not found"})
        return
    page_id, resource_id, action_id = parts
    with runtime.page_action_lock(page_id):
        page = handler._load_page(page_id)
        if page is not None and handler._require_preview_access(page):
            rate_key = f"{page_id}:{handler.camera_access_scope}:{handler.client_address[0]}"
            if not runtime.PREVIEW_ACTION_RATE_LIMITER.allow(rate_key):
                handler._send_json(runtime.HTTPStatus.TOO_MANY_REQUESTS, {"error": "Too many preview actions"})
                return
            handler._execute_public_action(page, resource_id, action_id, payload)
