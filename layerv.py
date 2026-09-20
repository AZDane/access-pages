import json
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from urllib.parse import quote, urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class LayerVError(RuntimeError):
    def __init__(self, message, status=None, detail=None, retry_after=None):
        super().__init__(message)
        self.status = status
        self.detail = detail
        self.retry_after = retry_after


def retry_delay(value):
    """Parse Retry-After without treating pending enforcement as success."""
    try:
        return max(0, int(value))
    except (ValueError, TypeError):
        try:
            return max(0, int((parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()))
        except (ValueError, TypeError, OverflowError):
            return None


class LayerVClient:
    def __init__(self, api_base_url: str, api_token: str, resource_id: str, *, resource_public_key: str = "", resource_scope: str = "guest"):
        self.api_base_url = api_base_url.rstrip("/")
        self.api_token = api_token.strip()
        self.resource_id = resource_id.strip()
        self.resource_public_key = resource_public_key.strip()
        if resource_scope not in {"guest", "page"}:
            raise ValueError("Invalid LayerV resource isolation mode")
        self.resource_scope = resource_scope

    @property
    def configured(self) -> bool:
        return bool(
            self.api_base_url
            and self.api_token
            and self.resource_id
        )

    def mint_agent_enrollment_token(self) -> str:
        """Mint a one-shot agent credential with the retained installation key."""
        if not self.api_base_url or not self.api_token:
            raise LayerVError("LayerV enrollment credential is unavailable", status=503)
        request = Request(
            f"{self.api_base_url}/v1/api-keys",
            data=json.dumps({
                "kind": "enrollment_token",
                "name": "Access Pages agent enrollment",
                "target": "agent",
            }).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=20) as response:  # nosec B310
                result = json.load(response)
        except HTTPError as error:
            raise LayerVError(
                "LayerV rejected Agent enrollment token creation",
                status=error.code,
                retry_after=retry_delay(error.headers.get("Retry-After")),
            ) from error
        except (URLError, TimeoutError, ValueError) as error:
            raise LayerVError("LayerV Agent enrollment token is unavailable", status=503) from error
        data = result.get("data") if isinstance(result, dict) else None
        if (
            not isinstance(data, dict)
            or data.get("kind") != "enrollment_token"
            or data.get("target") != "agent"
            or not isinstance(data.get("api_key"), str)
            or not data["api_key"].startswith(("lv_live_", "lv_test_"))
        ):
            raise LayerVError("LayerV returned invalid Agent enrollment token data", status=503)
        return data["api_key"]

    def create_qurl(
        self,
        *,
        label: str,
        expires_in: str,
        one_time_use: bool = False,
        page_id: str = "",
        grant_id: str = "",
        target_path: str = "",
        target_path_supported: bool = False,
        session_duration: str = "1h",
    ) -> dict:
        if not self.configured:
            raise LayerVError(
                "LayerV API is not configured. Set "
                "LAYERV_API_TOKEN and LAYERV_RESOURCE_ID."
            )

        payload = {
            "expires_in": expires_in,
            "one_time_use": bool(one_time_use),
            "session_duration": session_duration,
        }
        requested_at = datetime.now(timezone.utc)

        if label:
            payload["label"] = label
        if target_path_supported and target_path:
            payload["target_path"] = target_path

        request = Request(
            (
                f"{self.api_base_url}/v1/resources/"
                f"{quote(self.resource_id, safe='')}/qurls"
            ),
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

        try:
            # The base URL is administrator-controlled LayerV API config.
            with urlopen(request, timeout=20) as response:  # nosec B310
                raw = response.read().decode("utf-8")
                result = json.loads(raw)
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            delay = retry_delay(error.headers.get("Retry-After"))
            message = f"LayerV rejected qURL creation ({error.code})"
            if error.code == 429:
                message = "LayerV qURL creation rate limit reached (429)"
                message += f"; wait {delay} seconds before retrying" if delay is not None else "; wait for the account rate-limit window before retrying"
            elif error.code == 403:
                try:
                    problem = json.loads(detail)
                    if isinstance(problem, dict) and isinstance(problem.get("error"), dict) and problem["error"].get("code") == "quota_exceeded":
                        message = "LayerV account quota exceeded; resolve the plan limit before retrying (403)"
                except ValueError:
                    pass
            raise LayerVError(
                message,
                status=error.code,
                detail=detail,
                retry_after=delay,
            ) from error
        except TimeoutError as error:
            raise LayerVError("LayerV request timed out; reconciliation pending", status=503, retry_after=2) from error
        except URLError as error:
            raise LayerVError(
                f"Could not reach LayerV API: {error.reason}"
            ) from error
        except json.JSONDecodeError as error:
            raise LayerVError(
                "LayerV returned an invalid JSON response"
            ) from error

        data = result.get("data") if isinstance(result, dict) else None
        if not isinstance(data, dict):
            raise LayerVError("LayerV response did not contain qURL data")

        qurl_link = data.get("qurl_link") or data.get("qurl")
        if not qurl_link:
            raise LayerVError("LayerV response did not contain a qURL link")

        if target_path_supported and target_path:
            if data.get("target_path") != target_path:
                raise LayerVError("LayerV did not confirm the requested target path")
            if data.get("resource_id") != (self.resource_public_key or self.resource_id):
                raise LayerVError("LayerV response resource does not match the request")
            try:
                deadline = datetime.fromisoformat(str(data["expires_at"]).replace("Z", "+00:00"))
                amount, unit = int(expires_in[:-1]), expires_in[-1]
                duration = timedelta(seconds=amount * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[unit])
                if deadline.tzinfo is None or deadline <= requested_at or deadline > requested_at + duration + timedelta(seconds=5):
                    raise ValueError("Invalid effective expiry")
            except (KeyError, ValueError, TypeError, OverflowError) as error:
                raise LayerVError("LayerV returned an invalid effective expiry") from error

        qurl_id = (
            data.get("qurl_id")
            or data.get("qurl_display_id")
            or data.get("display_id")
            or data.get("id")
            or ""
        )
        if self.resource_public_key and target_path_supported:
            # Creation echoes the scope and expiry but omits these effective
            # admission settings. Verify them through independent inventory.
            rows = self.list_qurls(resource_crid=self.resource_id)
            confirmed = next((row for row in rows if isinstance(row, dict) and row.get("qurl_id") == qurl_id), None)
            try:
                duration_seconds = int(session_duration[:-1]) * {"s": 1, "m": 60, "h": 3600}[session_duration[-1]]
            except (ValueError, KeyError, IndexError) as error:
                raise LayerVError("Invalid requested admission duration") from error
            if (
                not confirmed
                or confirmed.get("one_time_use") is not bool(one_time_use)
                or type(confirmed.get("session_duration")) is not int
                or confirmed["session_duration"] != duration_seconds
                or confirmed.get("target_path") != target_path
            ):
                raise LayerVError("LayerV did not confirm effective invitation settings", status=503, retry_after=2)

        return {
            "qurl_id": str(qurl_id),
            "qurl_link": str(qurl_link),
            "qurl_site": str(data.get("qurl_site") or ""),
            "resource_id": str(data.get("resource_id") or ""),
            "expires_at": str(data.get("expires_at") or ""),
            "type": str(data.get("type") or ""),
            "label": str(data.get("label") or label or ""),
            "one_time_use": bool(one_time_use),
            "target_path_applied": bool(
                target_path_supported and target_path
            ),
            "target_path": str(data.get("target_path") or ""),
            **({"resource_crid": self.resource_id, "upstream_scope": self.resource_scope} if self.resource_public_key else {}),
        }

    def list_qurls(self, *, resource_crid):
        """Read every page; a short response does not imply completion."""
        cursor = ""
        seen = set()
        rows = []
        for _ in range(1000):
            query = {"limit": 100}
            if cursor:
                query["cursor"] = cursor
            request = Request(
                f"{self.api_base_url}/v1/resources/{quote(resource_crid, safe='')}/qurls?{urlencode(query)}",
                headers={"Authorization": f"Bearer {self.api_token}", "Accept": "application/json"},
            )
            try:
                with urlopen(request, timeout=20) as response:  # nosec B310
                    result = json.loads(response.read())
            except HTTPError as error:
                if error.code in {404, 410}:
                    return []
                raise LayerVError("LayerV invitation inventory is unavailable", status=error.code, retry_after=retry_delay(error.headers.get("Retry-After"))) from error
            except (URLError, ValueError, TimeoutError) as error:
                raise LayerVError("LayerV invitation inventory is unavailable", status=503) from error
            if not isinstance(result, dict) or not isinstance(result.get("data"), list) or not isinstance(result.get("meta"), dict):
                raise LayerVError("LayerV returned invalid invitation inventory")
            rows.extend(result["data"])
            meta = result["meta"]
            if meta.get("has_more") is False:
                return rows
            cursor = meta.get("next_cursor")
            if not isinstance(cursor, str) or not cursor or cursor in seen:
                raise LayerVError("LayerV returned invalid inventory pagination")
            seen.add(cursor)
        raise LayerVError("LayerV invitation inventory exceeded safe pagination limit")

    def delete_resource(self, *, resource_crid: str) -> bool:
        """Revoke an owned guest resource, including every invitation on it."""
        if not self.api_base_url or not self.api_token or not resource_crid.strip():
            raise LayerVError("LayerV management credential and resource CRID are required")
        request = Request(
            f"{self.api_base_url}/v1/resources/{quote(resource_crid.strip(), safe='')}",
            method="DELETE",
            headers={"Authorization": f"Bearer {self.api_token}", "Accept": "application/json"},
        )
        try:
            with urlopen(request, timeout=20) as response:  # nosec B310
                response.read()
        except HTTPError as error:
            if error.code in (404, 410):
                return True
            raise LayerVError(
                f"LayerV rejected resource revocation ({error.code})",
                status=error.code,
                retry_after=retry_delay(error.headers.get("Retry-After")),
            ) from error
        except TimeoutError as error:
            raise LayerVError("LayerV resource revocation timed out; reconciliation pending", status=503, retry_after=2) from error
        except URLError as error:
            raise LayerVError("Could not reach LayerV for resource revocation") from error
        return False
    def delete_qurl(
        self,
        *,
        resource_id: str = "",
        qurl_id: str,
        page_id: str = "",
        grant_id: str = "",
    ) -> bool:
        """Delete one qURL from LayerV.

        Keep the issued resource locator and individual qURL ID distinct.
        Return True when LayerV reports that the qURL was already absent.
        """
        effective_resource_id = (resource_id or self.resource_id).strip()
        qurl_id = qurl_id.strip()
        if not self.api_base_url or not self.api_token:
            raise LayerVError("LayerV API is not configured")
        if not effective_resource_id or not qurl_id:
            raise LayerVError("LayerV resource ID and qURL ID are required")

        request = Request(
            (
                f"{self.api_base_url}/v1/resources/"
                f"{quote(effective_resource_id, safe='')}/qurls/{quote(qurl_id, safe='')}"
            ),
            method="DELETE",
            headers={
                "Authorization": f"Bearer {self.api_token}",
                "Accept": "application/json",
            },
        )

        try:
            # The base URL is administrator-controlled LayerV API config.
            with urlopen(request, timeout=20) as response:  # nosec B310
                response.read()
        except HTTPError as error:
            # Deletion is idempotent from the gateway's perspective. A qURL
            # already absent at LayerV is considered successfully revoked.
            if error.code in (404, 410):
                return True
            detail = error.read().decode("utf-8", errors="replace")
            raise LayerVError(
                f"LayerV rejected qURL deletion ({error.code})",
                status=error.code,
                detail=detail,
                retry_after=retry_delay(error.headers.get("Retry-After")),
            ) from error
        except TimeoutError as error:
            raise LayerVError("LayerV qURL deletion timed out; reconciliation pending", status=503, retry_after=2) from error
        except URLError as error:
            raise LayerVError(
                f"Could not reach LayerV API: {error.reason}"
            ) from error
        return False


class BrokerLayerVClient:
    def recovery_required(self):
        try:
            self._request("GET", "/health")
        except LayerVError as error:
            try:
                return json.loads(error.detail or "{}").get("recovery_required") is True
            except ValueError:
                return False
        return False

    def queue_revocation(self, *, page_id, grant_id):
        return self._request("DELETE", f"/v1/grants/{page_id}/{grant_id}?defer=15")

    def __init__(self, broker_url, broker_token, resource_id=""):
        self.api_base_url = broker_url.rstrip("/")
        self.api_token = broker_token.strip()
        self.resource_id = resource_id.strip()

    @property
    def configured(self):
        return bool(self.api_base_url and self.api_token)

    def _request(self, method, path, payload=None):
        data = None
        headers = {
            "X-Broker-Token": self.api_token,
            "Accept": "application/json",
        }
        if payload is not None:
            data = json.dumps(payload).encode()
            headers["Content-Type"] = "application/json"
        request = Request(
            f"{self.api_base_url}{path}",
            data=data,
            method=method,
            headers=headers,
        )
        try:
            # Cold native enrollment, first publication and daemon readiness
            # are sequential bounded operations. Keep their response attached
            # to the owner request instead of abandoning it after 20 seconds.
            timeout = (360 if method == "POST" and path == "/v1/grants"
                       else 2 if path == "/health" else 20)
            with urlopen(request, timeout=timeout) as response:  # nosec B310
                body = response.read()
                return json.loads(body) if body else {}
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            message = "LayerV integration broker rejected the request"
            status = error.code
            try:
                broker_error = json.loads(detail)
                # This is our authenticated private broker's bounded error,
                # never the upstream response detail or Connector stderr.
                if isinstance(broker_error, dict):
                    explanation = broker_error.get("error")
                    if isinstance(explanation, str) and 0 < len(explanation) <= 512:
                        message = explanation
                    upstream_status = broker_error.get("layerv_status")
                    if type(upstream_status) is int and 400 <= upstream_status <= 599:
                        status = upstream_status
            except ValueError:
                pass
            raise LayerVError(
                message,
                status=status,
                detail=detail,
                retry_after=retry_delay(error.headers.get("Retry-After")),
            ) from error
        except TimeoutError as error:
            raise LayerVError("LayerV integration broker request timed out; reconciliation pending", status=503, retry_after=2) from error
        except URLError as error:
            raise LayerVError(
                f"Could not reach LayerV integration broker: {error.reason}"
            ) from error

    def create_qurl(
        self,
        *,
        label,
        expires_in,
        one_time_use=False,
        page_id="",
        grant_id="",
        target_path="",
        target_path_supported=False,
        session_duration="1h",
    ):
        if not page_id or not grant_id:
            raise LayerVError("LayerV integration broker requires a saved page and grant")
        return self._request(
            "POST",
            "/v1/grants",
            {
                "page_id": page_id,
                "grant_id": grant_id,
                "label": label,
                "expires_in": expires_in,
                "target_path": target_path,
                "one_time_use": bool(one_time_use),
                "session_duration": session_duration,
            },
        )

    def delete_qurl(
        self,
        *,
        resource_id="",
        qurl_id="",
        page_id="",
        grant_id="",
    ):
        if not page_id or not grant_id:
            raise LayerVError("LayerV integration broker requires a stored grant")
        result = self._request(
            "DELETE",
            f"/v1/grants/{page_id}/{grant_id}?defer=15",
        )
        return bool(result.get("already_missing", False))
