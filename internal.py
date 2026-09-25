"""Authenticated broker events and configured Admin-owned delivery."""


SECURITY_EVENTS = frozenset({
    "action_rate_limited", "unapproved_action_attempt",
    "verification_code_sent", "guest_email_verified", "verification_failed",
})
ACTION_EVENTS = frozenset({"action_success", "action_failed"})


def _notify_guest_event(runtime, page_id, grant_id, event, details):
    try:
        page = runtime.PAGE_STORE.load(page_id)
    except (runtime.PageNotFoundError, runtime.PageConfigError, OSError):
        return
    grant = next((item for item in page["access_grants"]
                  if item["id"] == grant_id), None)
    if not grant:
        return
    settings = grant.get("notifications") or {}
    event_key = (
        "initial_login" if event == "initial_access" else
        "successful_action" if event == "action_success" else
        "failed_action" if event in {"action_failed", "action_rate_limited",
                                     "unapproved_action_attempt"} else ""
    )
    if event_key not in settings.get("events", []):
        return
    guest = grant.get("label") or "A guest"
    if event_key == "initial_login":
        message = f"{guest} opened {page['title']} for the first time."
    else:
        resource = next((item for item in page["resources"]
                         if item["id"] == details.get("resource_id")), None)
        action = next((item for item in (resource or {}).get("actions", [])
                       if item["id"] == details.get("action_id")), None)
        entity = (resource or {}).get("name") or "an unavailable entity"
        operation = (action or {}).get("name") or "an unapproved action"
        result = "succeeded" if event_key == "successful_action" else "failed or was blocked"
        message = f"{guest} used {entity}: {operation} {result}."
    title = "Access Pages activity"
    try:
        allowed_mobile = set(runtime.NOTIFICATION_TARGET_STORE.load())
        for target in settings.get("targets", []):
            if target == "email":
                config = runtime.SMTP_CONFIG_STORE.load()
                runtime.send_email(config, config.administrator_email,
                                   title, message + "\n")
            elif target in allowed_mobile:
                runtime.HA_CLIENT.send_notification(target, title, message)
    except (runtime.EmailConfigError, runtime.HomeAssistantError, OSError):
        runtime.audit("guest_notification_failed", page_id=page_id,
                      grant_id=grant_id, event_type=event_key)


def _guest_event(handler, payload, runtime):
    allowed = {"page_id", "grant_id", "event"}
    event = payload.get("event")
    if not isinstance(event, str):
        handler._send_json(runtime.HTTPStatus.BAD_REQUEST, {"error": "Invalid guest event"})
        return
    if event in ACTION_EVENTS:
        allowed |= {"resource_id", "action_id", "entity_id", "entity_name",
                    "parameters"}
    elif event == "unapproved_action_attempt":
        allowed.add("reason")
    elif event not in SECURITY_EVENTS | {"initial_access"}:
        handler._send_json(runtime.HTTPStatus.BAD_REQUEST, {"error": "Invalid guest event"})
        return
    page_id, grant_id = payload.get("page_id"), payload.get("grant_id")
    if (set(payload) != allowed or not isinstance(page_id, str)
            or not runtime.re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", page_id)
            or not isinstance(grant_id, str)
            or not runtime.re.fullmatch(r"grant_[A-Za-z0-9_-]{16}", grant_id)):
        handler._send_json(runtime.HTTPStatus.BAD_REQUEST, {"error": "Invalid guest event"})
        return
    details = {}
    if event in ACTION_EVENTS:
        for key in ("resource_id", "action_id"):
            if not isinstance(payload[key], str) or not runtime.re.fullmatch(
                r"[a-z0-9][a-z0-9_-]{0,63}", payload[key]
            ):
                handler._send_json(runtime.HTTPStatus.BAD_REQUEST, {"error": "Invalid guest event"})
                return
        if (not isinstance(payload["entity_id"], str)
                or len(payload["entity_id"]) > 255
                or not isinstance(payload["entity_name"], str)
                or len(payload["entity_name"]) > 120
                or not isinstance(payload["parameters"], dict)):
            handler._send_json(runtime.HTTPStatus.BAD_REQUEST, {"error": "Invalid guest event"})
            return
        details = {key: payload[key] for key in allowed - {"page_id", "grant_id", "event"}}
    elif event == "unapproved_action_attempt":
        if (not isinstance(payload["reason"], str)
                or payload["reason"] not in {"resource_not_assigned", "action_not_permitted"}):
            handler._send_json(runtime.HTTPStatus.BAD_REQUEST, {"error": "Invalid guest event"})
            return
        details = {"reason": payload["reason"]}
    try:
        if event == "initial_access":
            first = runtime.ACTIVITY_STORE.record_registered_initial_access(page_id, grant_id)
            if first:
                _notify_guest_event(runtime, page_id, grant_id, event, details)
        elif event in ACTION_EVENTS:
            if event == "action_success":
                runtime.audit(
                    "action_executed", page_id=page_id, grant_id=grant_id,
                    resource_id=details["resource_id"],
                    entity_id=details["entity_id"], action_id=details["action_id"],
                )
            runtime.ACTIVITY_STORE.record_action(
                grant_id=grant_id, entity_id=details["entity_id"],
                entity_name=details["entity_name"], action_id=details["action_id"],
                parameters=details["parameters"],
                outcome="success" if event == "action_success" else "failed",
                error="" if event == "action_success" else (
                    "The action could not be confirmed. "
                    "Check the current state before trying again."
                ),
            )
            if event == "action_failed":
                runtime.ACTIVITY_STORE.record_security_event(
                    page_id=page_id, grant_id=grant_id,
                    event_type="home_assistant_action_rejected",
                    details={"resource_id": details["resource_id"],
                             "action_id": details["action_id"]},
                )
            _notify_guest_event(runtime, page_id, grant_id, event, details)
        else:
            if event == "action_rate_limited":
                runtime.audit("action_rate_limited", page_id=page_id,
                              grant_id=grant_id)
            runtime.ACTIVITY_STORE.record_security_event(
                page_id=page_id, grant_id=grant_id,
                event_type=event,
                details={"reason": details.get("reason", "request_limit_exceeded")}
                if event in {"action_rate_limited", "unapproved_action_attempt"} else {},
            )
            if event in {"action_rate_limited", "unapproved_action_attempt"}:
                _notify_guest_event(runtime, page_id, grant_id, event, details)
    except (OSError, runtime.sqlite3.Error, ValueError):
        runtime.audit("guest_activity_storage_failed", page_id=page_id,
                      grant_id=grant_id, operation=event)
        handler._send_json(runtime.HTTPStatus.SERVICE_UNAVAILABLE,
                           {"error": "Activity storage unavailable"})
        return
    handler._send_json(200, {"success": True})


def handle_post(handler, path, payload, runtime):
    if path not in {"/api/internal/email/guest-verification",
                    "/api/internal/guest-event"}:
        handler._send_json(404, {"error": "not found"})
        return
    tokens = handler.headers.get_all("X-HA-Broker-Token", [])
    if not (
        len(tokens) == 1 and runtime.HA_BROKER_TOKEN
        and runtime.hmac.compare_digest(tokens[0], runtime.HA_BROKER_TOKEN)
    ):
        handler._send_json(runtime.HTTPStatus.UNAUTHORIZED, {"error": "not found"})
        return
    if path == "/api/internal/guest-event":
        _guest_event(handler, payload, runtime)
        return
    if set(payload) != {"page_id", "grant_id", "code"}:
        handler._send_json(runtime.HTTPStatus.BAD_REQUEST, {"error": "Invalid delivery request"})
        return
    page_id = str(payload["page_id"])
    grant_id = str(payload["grant_id"])
    code = str(payload["code"])
    page = handler._load_page(page_id)
    if page is None:
        return
    grant = next((item for item in page["access_grants"] if item["id"] == grant_id), None)
    if (
        not grant or not grant.get("verification_required")
        or grant.get("credential_flow") != "bootstrap-v1"
        or runtime.parse_time(grant["expires_at"]) <= runtime.utc_now()
        or not runtime.re.fullmatch(r"\d{6}", code)
    ):
        handler._send_json(runtime.HTTPStatus.NOT_FOUND, {"error": "not found"})
        return
    try:
        text, html = runtime.verification_email_content(code)
        runtime.send_email(
            runtime.SMTP_CONFIG_STORE.load(),
            runtime.VERIFICATION_RECIPIENTS.get(page_id, grant_id),
            "Your Access Pages verification code",
            text,
            html_body=html,
        )
        handler._send_json(200, {"success": True})
    except runtime.EmailConfigError as error:
        handler._send_json(runtime.HTTPStatus.BAD_GATEWAY, {"error": str(error)})
