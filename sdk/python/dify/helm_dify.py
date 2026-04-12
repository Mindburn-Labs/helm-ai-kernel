"""
HELM governance adapter for Dify platform.

HTTP middleware (WSGI/ASGI) that intercepts tool calls to the Dify backend
and routes them through HELM's governance plane. Supports fail-closed mode,
receipt collection, and both Flask and ASGI frameworks.

Usage:
    from helm_dify import HelmDifyGovernor, HelmDifyMiddleware

    # Flask middleware
    app = Flask(__name__)
    governor = HelmDifyGovernor(helm_url="http://localhost:8080")
    app.wsgi_app = HelmDifyMiddleware(app.wsgi_app, governor)

    # Or govern tool calls directly
    governor.govern_tool("web_search", {"query": "test"})
"""

from __future__ import annotations

import hashlib
import json
import time
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence
from io import BytesIO

import httpx


@dataclass
class HelmDifyConfig:
    """Configuration for HELM Dify governance."""

    helm_url: str = "http://localhost:8080"
    api_key: Optional[str] = None
    fail_closed: bool = True
    collect_receipts: bool = True
    timeout: float = 30.0
    governed_paths: list[str] = field(
        default_factory=lambda: ["/v1/chat-messages", "/v1/workflows/run"]
    )


@dataclass
class ToolCallReceipt:
    """A receipt for a governed tool call."""

    tool_name: str
    args: dict[str, Any]
    receipt_id: str
    decision: str  # "APPROVED" | "DENIED"
    reason_code: str
    duration_ms: float
    request_hash: str
    output_hash: str
    lamport_clock: int = 0


@dataclass
class ToolCallDenial:
    """Details of a denied tool call."""

    tool_name: str
    args: dict[str, Any]
    reason_code: str
    message: str


class HelmToolDenyError(Exception):
    """Raised when HELM denies a tool call."""

    def __init__(self, denial: ToolCallDenial):
        super().__init__(
            f'HELM denied tool call "{denial.tool_name}": '
            f"{denial.reason_code} — {denial.message}"
        )
        self.denial = denial


class HelmDifyGovernor:
    """
    Governs Dify platform tool calls through HELM.

    Evaluates tool invocations against HELM policy. Can be used standalone
    or via the HelmDifyMiddleware for automatic HTTP interception.
    """

    def __init__(self, config: Optional[HelmDifyConfig] = None, **kwargs: Any):
        if config is None:
            config = HelmDifyConfig(**kwargs)
        self.config = config
        self._receipts: list[ToolCallReceipt] = []
        self._on_receipt: Optional[Callable[[ToolCallReceipt], None]] = None
        self._on_deny: Optional[Callable[[ToolCallDenial], None]] = None
        self._lamport = 0
        self._lock = threading.Lock()

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if config.api_key:
            headers["Authorization"] = f"Bearer {config.api_key}"
        self._client = httpx.Client(
            base_url=config.helm_url,
            headers=headers,
            timeout=config.timeout,
        )

    def on_receipt(self, callback: Callable[[ToolCallReceipt], None]) -> "HelmDifyGovernor":
        """Register a callback for tool call receipts."""
        self._on_receipt = callback
        return self

    def on_deny(self, callback: Callable[[ToolCallDenial], None]) -> "HelmDifyGovernor":
        """Register a callback for denied tool calls."""
        self._on_deny = callback
        return self

    @property
    def receipts(self) -> list[ToolCallReceipt]:
        """Get all collected receipts."""
        return list(self._receipts)

    def clear_receipts(self) -> None:
        """Clear collected receipts."""
        self._receipts.clear()

    def govern_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """
        Evaluate a Dify tool call through HELM governance.

        Args:
            tool_name: The tool or workflow name
            arguments: The tool arguments / workflow inputs

        Returns:
            The HELM governance response

        Raises:
            HelmToolDenyError: If the call is denied
        """
        start_ms = time.monotonic() * 1000

        with self._lock:
            self._lamport += 1
            lamport = self._lamport

        try:
            response = self._evaluate_intent(tool_name, arguments)

            choices = response.get("choices", [])
            if not choices or (
                choices[0].get("finish_reason") == "stop"
                and not choices[0].get("message", {}).get("tool_calls")
            ):
                denial = ToolCallDenial(
                    tool_name=tool_name,
                    args=arguments,
                    reason_code="DENY_POLICY_VIOLATION",
                    message="Denied by HELM governance",
                )
                if self._on_deny:
                    self._on_deny(denial)
                raise HelmToolDenyError(denial)

            duration_ms = time.monotonic() * 1000 - start_ms
            request_hash = "sha256:" + hashlib.sha256(
                json.dumps(arguments, sort_keys=True, default=str).encode()
            ).hexdigest()

            receipt = ToolCallReceipt(
                tool_name=tool_name,
                args=arguments,
                receipt_id=response.get("id", ""),
                decision="APPROVED",
                reason_code="ALLOW",
                duration_ms=duration_ms,
                request_hash=request_hash,
                output_hash="",
                lamport_clock=lamport,
            )

            if self.config.collect_receipts:
                self._receipts.append(receipt)
            if self._on_receipt:
                self._on_receipt(receipt)

            return response

        except HelmToolDenyError:
            raise
        except httpx.HTTPError as e:
            if self.config.fail_closed:
                raise HelmToolDenyError(
                    ToolCallDenial(
                        tool_name=tool_name,
                        args=arguments,
                        reason_code="ERROR_INTERNAL",
                        message=str(e),
                    )
                ) from e
            return {"choices": [{"message": {"tool_calls": []}}]}

    def govern_request_body(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        """
        Govern a Dify API request body before it reaches the backend.

        Extracts tool/workflow information from the request and evaluates
        through HELM.

        Args:
            path: The HTTP request path (e.g., /v1/chat-messages)
            body: The parsed JSON request body

        Returns:
            The HELM governance response

        Raises:
            HelmToolDenyError: If the request is denied
        """
        # Extract tool name from path and body
        if "/workflows/" in path:
            tool_name = body.get("workflow_id", "dify-workflow")
        else:
            tool_name = "dify-chat"

        # Include relevant inputs as arguments
        arguments = {}
        if "inputs" in body:
            arguments["inputs"] = body["inputs"]
        if "query" in body:
            arguments["query"] = body["query"]
        if "tools" in body:
            arguments["tools"] = body["tools"]

        return self.govern_tool(tool_name, arguments)

    def _evaluate_intent(self, tool_name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Send a tool call intent to HELM for policy evaluation."""
        intent = {
            "model": "helm-governance",
            "messages": [
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "type": "tool_call_intent",
                            "tool": tool_name,
                            "arguments": args,
                            "principal": "dify-platform",
                        }
                    ),
                }
            ],
            "tools": [
                {
                    "type": "function",
                    "function": {"name": tool_name},
                }
            ],
        }
        resp = self._client.post("/v1/chat/completions", json=intent)
        if resp.status_code >= 400:
            body = resp.json()
            err = body.get("error", {})
            raise HelmToolDenyError(
                ToolCallDenial(
                    tool_name=tool_name,
                    args=args,
                    reason_code=err.get("reason_code", "ERROR_INTERNAL"),
                    message=err.get("message", resp.text),
                )
            )
        return resp.json()

    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self) -> "HelmDifyGovernor":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


class HelmDifyMiddleware:
    """
    WSGI middleware that intercepts Dify API requests for HELM governance.

    Sits between a WSGI application (e.g., Flask) and the HTTP server.
    Intercepts requests to governed paths and evaluates them through HELM
    before forwarding to the application.

    Usage:
        app = Flask(__name__)
        governor = HelmDifyGovernor(helm_url="http://localhost:8080")
        app.wsgi_app = HelmDifyMiddleware(app.wsgi_app, governor)
    """

    def __init__(self, app: Any, governor: HelmDifyGovernor):
        self._app = app
        self._governor = governor

    def __call__(self, environ: dict, start_response: Callable) -> Any:
        """WSGI entry point."""
        path = environ.get("PATH_INFO", "")

        # Only govern configured paths
        if not any(path.startswith(p) for p in self._governor.config.governed_paths):
            return self._app(environ, start_response)

        # Only govern POST/PUT requests with JSON bodies
        method = environ.get("REQUEST_METHOD", "GET")
        if method not in ("POST", "PUT"):
            return self._app(environ, start_response)

        content_type = environ.get("CONTENT_TYPE", "")
        if "application/json" not in content_type:
            return self._app(environ, start_response)

        try:
            content_length = int(environ.get("CONTENT_LENGTH", 0))
            body_bytes = environ["wsgi.input"].read(content_length)
            body = json.loads(body_bytes) if body_bytes else {}

            # Evaluate through HELM
            self._governor.govern_request_body(path, body)

            # Reset input stream for the downstream app
            environ["wsgi.input"] = BytesIO(body_bytes)
            environ["CONTENT_LENGTH"] = str(len(body_bytes))
            return self._app(environ, start_response)

        except HelmToolDenyError as e:
            error_body = json.dumps({
                "error": {
                    "message": str(e),
                    "reason_code": e.denial.reason_code,
                    "type": "helm_governance_denied",
                }
            }).encode()
            start_response(
                "403 Forbidden",
                [
                    ("Content-Type", "application/json"),
                    ("Content-Length", str(len(error_body))),
                ],
            )
            return [error_body]

        except (json.JSONDecodeError, ValueError):
            # Cannot parse body — pass through or deny based on config
            if self._governor.config.fail_closed:
                error_body = json.dumps({
                    "error": {
                        "message": "HELM: unable to parse request body for governance",
                        "reason_code": "ERROR_PARSE",
                        "type": "helm_governance_error",
                    }
                }).encode()
                start_response(
                    "400 Bad Request",
                    [
                        ("Content-Type", "application/json"),
                        ("Content-Length", str(len(error_body))),
                    ],
                )
                return [error_body]
            return self._app(environ, start_response)


class HelmDifyASGIMiddleware:
    """
    ASGI middleware that intercepts Dify API requests for HELM governance.

    For use with ASGI frameworks (FastAPI, Starlette, etc.).

    Usage:
        from fastapi import FastAPI
        app = FastAPI()
        governor = HelmDifyGovernor(helm_url="http://localhost:8080")
        app.add_middleware(HelmDifyASGIMiddleware, governor=governor)
    """

    def __init__(self, app: Any, governor: HelmDifyGovernor):
        self._app = app
        self._governor = governor

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        """ASGI entry point."""
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET")

        if method not in ("POST", "PUT") or not any(
            path.startswith(p) for p in self._governor.config.governed_paths
        ):
            await self._app(scope, receive, send)
            return

        # Collect request body
        body_parts = []
        while True:
            message = await receive()
            body_parts.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        body_bytes = b"".join(body_parts)

        try:
            body = json.loads(body_bytes) if body_bytes else {}
            self._governor.govern_request_body(path, body)
        except HelmToolDenyError as e:
            error_body = json.dumps({
                "error": {
                    "message": str(e),
                    "reason_code": e.denial.reason_code,
                    "type": "helm_governance_denied",
                }
            }).encode()
            await send({
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    [b"content-type", b"application/json"],
                    [b"content-length", str(len(error_body)).encode()],
                ],
            })
            await send({
                "type": "http.response.body",
                "body": error_body,
            })
            return
        except (json.JSONDecodeError, ValueError):
            if self._governor.config.fail_closed:
                error_body = json.dumps({
                    "error": {
                        "message": "HELM: unable to parse request body for governance",
                        "reason_code": "ERROR_PARSE",
                        "type": "helm_governance_error",
                    }
                }).encode()
                await send({
                    "type": "http.response.start",
                    "status": 400,
                    "headers": [
                        [b"content-type", b"application/json"],
                        [b"content-length", str(len(error_body)).encode()],
                    ],
                })
                await send({
                    "type": "http.response.body",
                    "body": error_body,
                })
                return

        # Replay the body for the downstream app
        body_sent = False

        async def replay_receive() -> dict:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": body_bytes, "more_body": False}
            return await receive()

        await self._app(scope, replay_receive, send)
