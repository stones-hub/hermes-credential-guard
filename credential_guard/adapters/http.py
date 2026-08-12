"""R3A structured HTTPS adapter — binding-owned URL, header inject, no redirects."""

from __future__ import annotations

import base64
import json
import re
from typing import Any, Callable, Dict, Mapping, MutableMapping, Optional

from ..injection import InjectionError, SecretLease
from ..reference_tools import validate_http_method, validate_http_path
from ..registry import CredentialRegistry
from ..result_guard import RESULT_GUARD_FAIL_TEXT, guard_tool_result

TransportFn = Callable[[Dict[str, Any]], Dict[str, Any]]

_SAFE_RESPONSE_HEADERS = frozenset(
    {
        "content-type",
        "content-length",
        "date",
        "cache-control",
        "etag",
        "x-request-id",
    }
)
_FORBIDDEN_MODEL_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "authorization",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "cookie",
    }
)
_DOT_SEGMENT = re.compile(r"(?:^|/)\.(?:\./|/|$)|(?:^|/)\.\.(?:/|$)")
_PERCENT_DOT = re.compile(r"%2e", re.IGNORECASE)


class HttpAdapterError(Exception):
    def __init__(self, code: str) -> None:
        self.code = str(code)
        super().__init__(self.code)

    def __repr__(self) -> str:
        return f"HttpAdapterError({self.code!r})"


def _safe_fail(code: str = "HTTP_ADAPTER_FAILED") -> Dict[str, Any]:
    return {"ok": False, "error": code, "source": "credential-guard"}


def _validate_relative_path(path: str) -> str:
    try:
        path_s = validate_http_path(path)
    except ValueError as exc:
        raise HttpAdapterError("HTTP_PATH_REJECTED") from exc
    if _DOT_SEGMENT.search(path_s) or _PERCENT_DOT.search(path_s):
        raise HttpAdapterError("HTTP_PATH_REJECTED")
    # Percent-encoded slash / backslash / authority confusion.
    lowered = path_s.lower()
    if "%2f" in lowered or "%5c" in lowered or "%00" in lowered:
        raise HttpAdapterError("HTTP_PATH_REJECTED")
    return path_s


def _header_has_ctl(value: str) -> bool:
    return any(ch in value for ch in ("\r", "\n", "\x00"))


def _build_auth_headers(
    inject: Mapping[str, Any], lease: SecretLease
) -> Dict[str, str]:
    material = lease.read_for_adapter()
    itype = inject.get("type")
    try:
        if itype == "bearer":
            if material.get("kind") != "token":
                raise HttpAdapterError("HTTP_INJECT_MISMATCH")
            value = material["value"]
            if not isinstance(value, str) or not value or _header_has_ctl(value):
                raise HttpAdapterError("HTTP_INJECT_MISMATCH")
            return {"Authorization": f"Bearer {value}"}
        if itype == "basic":
            if material.get("kind") != "username_password":
                raise HttpAdapterError("HTTP_INJECT_MISMATCH")
            user = material["username"]
            password = material["password"]
            if not isinstance(user, str) or not isinstance(password, str):
                raise HttpAdapterError("HTTP_INJECT_MISMATCH")
            if _header_has_ctl(user) or _header_has_ctl(password):
                raise HttpAdapterError("HTTP_INJECT_MISMATCH")
            token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode(
                "ascii"
            )
            return {"Authorization": f"Basic {token}"}
        if itype == "api_key_header":
            if material.get("kind") != "token":
                raise HttpAdapterError("HTTP_INJECT_MISMATCH")
            header_name = inject.get("header_name")
            value = material["value"]
            if not isinstance(header_name, str) or not header_name:
                raise HttpAdapterError("HTTP_INJECT_MISMATCH")
            if header_name.lower() in _FORBIDDEN_MODEL_HEADERS:
                raise HttpAdapterError("HTTP_INJECT_MISMATCH")
            if _header_has_ctl(header_name) or not isinstance(value, str):
                raise HttpAdapterError("HTTP_INJECT_MISMATCH")
            if _header_has_ctl(value):
                raise HttpAdapterError("HTTP_INJECT_MISMATCH")
            return {header_name: value}
        raise HttpAdapterError("HTTP_INJECT_MISMATCH")
    except HttpAdapterError:
        raise
    except Exception:
        raise HttpAdapterError("HTTP_INJECT_MISMATCH") from None


def _session_materials(
    credential_name: str, lease: SecretLease
) -> list[tuple[str, str]]:
    """Build short-lived (name, secret) pairs for the unified result guard."""
    try:
        mat = lease.read_for_adapter()
    except InjectionError:
        raise
    materials: list[tuple[str, str]] = []
    if mat.get("kind") == "token" and isinstance(mat.get("value"), str):
        materials.append((credential_name, mat["value"]))
    elif mat.get("kind") == "username_password":
        if isinstance(mat.get("password"), str):
            materials.append((credential_name, mat["password"]))
        if isinstance(mat.get("username"), str) and isinstance(mat.get("password"), str):
            materials.append((credential_name, f"{mat['username']}:{mat['password']}"))
    return materials


def _guard_text(text: str, materials: list[tuple[str, str]]) -> str:
    return guard_tool_result(text, CredentialRegistry(), session_materials=materials)

def _filter_response_headers(headers: Mapping[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        if key.lower() not in _SAFE_RESPONSE_HEADERS:
            continue
        if _header_has_ctl(key) or _header_has_ctl(value):
            continue
        out[key.lower()] = value
    return out


class _NoRedirectHandler:
    """HTTPRedirectHandler that refuses every redirect (no follow)."""

    @staticmethod
    def build():
        import urllib.request

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(  # noqa: ANN001
                self, req, fp, code, msg, headers, newurl
            ):
                return None

        return _NoRedirect()


def _build_production_opener(ctx, *, connect_timeout: float, deadline: float, scheme: str):
    """Construct opener with empty proxy, no-redirect, scheme-specific handler.

    ``connect_timeout`` applies to TCP connect; ``deadline`` (monotonic) bounds
    post-connect socket I/O. Never pass ``context=`` to ``opener.open``.
    Never install the default env-reading ProxyHandler.
    HTTPS uses TLS via HTTPSHandler(context=...); HTTP uses plain HTTPHandler
    (no TLS wrap — plaintext by design).
    """
    import http.client
    import socket
    import time
    import urllib.request

    if scheme not in {"http", "https"}:
        raise HttpAdapterError("HTTP_ADAPTER_FAILED")

    class _DeadlineHTTPConnection(http.client.HTTPConnection):
        def connect(self):  # noqa: ANN001
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("deadline")
            to = min(float(connect_timeout), remaining)
            self.sock = socket.create_connection(
                (self.host, self.port), to, self.source_address
            )
            if self._tunnel_host:
                try:
                    self._tunnel()
                except Exception:
                    self.sock.close()
                    raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.sock.close()
                raise TimeoutError("deadline")
            self.sock.settimeout(remaining)

    class _DeadlineHTTPSConnection(http.client.HTTPSConnection):
        def connect(self):  # noqa: ANN001
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("deadline")
            to = min(float(connect_timeout), remaining)
            sys_sock = socket.create_connection(
                (self.host, self.port), to, self.source_address
            )
            if self._tunnel_host:
                self.sock = sys_sock
                try:
                    self._tunnel()
                except Exception:
                    sys_sock.close()
                    raise
                sys_sock = self.sock
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                sys_sock.close()
                raise TimeoutError("deadline")
            sys_sock.settimeout(remaining)
            context = self._context if self._context is not None else ctx
            self.sock = context.wrap_socket(sys_sock, server_hostname=self.host)

    class _DeadlineHTTPHandler(urllib.request.HTTPHandler):
        def http_open(self, req):  # noqa: ANN001
            return self.do_open(_DeadlineHTTPConnection, req)

    class _DeadlineHTTPSHandler(urllib.request.HTTPSHandler):
        def __init__(self) -> None:
            super().__init__(context=ctx)

        def https_open(self, req):  # noqa: ANN001
            return self.do_open(_DeadlineHTTPSConnection, req, context=self._context)

    handlers = [
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler.build(),
    ]
    if scheme == "https":
        handlers.append(_DeadlineHTTPSHandler())
    else:
        handlers.append(_DeadlineHTTPHandler())
    return urllib.request.build_opener(*handlers)


# Fixed allowlist for deadline socket discovery (no arbitrary object-graph walk).
_SOCKET_DEADLINE_ATTRS = ("fp", "raw", "_sock")
_SOCKET_DEADLINE_MAX_DEPTH = 8
_SOCKET_DEADLINE_MIN_TIMEOUT = 1e-3


def _find_deadline_socket(reader: Any, *, max_depth: int = _SOCKET_DEADLINE_MAX_DEPTH):
    """Locate leaf socket under urllib OK / HTTPError nesting via fixed attrs only.

    Real shapes:
    - OK: HTTPResponse.fp.raw._sock
    - HTTPError: HTTPError.fp (HTTPResponse).fp.raw._sock
    """
    if reader is None:
        return None
    seen: set[int] = set()
    stack: list[tuple[Any, int]] = [(reader, 0)]
    while stack:
        obj, depth = stack.pop()
        if obj is None or depth > max_depth:
            continue
        oid = id(obj)
        if oid in seen:
            continue
        seen.add(oid)
        leaf = getattr(obj, "_sock", None)
        if leaf is not None:
            st = getattr(leaf, "settimeout", None)
            if callable(st):
                return leaf
        st_self = getattr(obj, "settimeout", None)
        if callable(st_self) and callable(getattr(obj, "fileno", None)):
            return obj
        if depth == max_depth:
            continue
        for name in _SOCKET_DEADLINE_ATTRS:
            child = getattr(obj, name, None)
            if child is not None and id(child) not in seen:
                stack.append((child, depth + 1))
    return None


def _read_body_with_deadline(reader, *, max_body: int, deadline: float) -> bytes:
    """Bounded body read under monotonic total deadline (OK response and HTTPError)."""
    import time

    if reader is None:
        return b""
    chunks: list[bytes] = []
    total = 0
    while total <= max_body:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise HttpAdapterError("HTTP_ADAPTER_FAILED")
        try:
            sock = _find_deadline_socket(reader)
            if sock is not None:
                sock.settimeout(max(remaining, _SOCKET_DEADLINE_MIN_TIMEOUT))
        except Exception:
            pass
        piece = reader.read(min(8192, max_body + 1 - total))
        if not piece:
            break
        chunks.append(piece)
        total += len(piece)
        if time.monotonic() > deadline:
            raise HttpAdapterError("HTTP_ADAPTER_FAILED")
    body = b"".join(chunks)
    if time.monotonic() > deadline:
        raise HttpAdapterError("HTTP_ADAPTER_FAILED")
    return body


def _default_transport(request: Dict[str, Any]) -> Dict[str, Any]:
    """Production HTTP/HTTPS transport: no env proxy, no redirects; HTTPS verify required."""
    import ssl
    import time
    import urllib.error
    import urllib.parse
    import urllib.request

    if request.get("allow_redirects"):
        raise HttpAdapterError("HTTP_ADAPTER_FAILED")
    if request.get("trust_env"):
        raise HttpAdapterError("HTTP_ADAPTER_FAILED")
    # Shared request contract: verify must stay True so callers cannot disable
    # HTTPS TLS via verify=False. Plain HTTP does not perform TLS.
    if request.get("verify") is not True:
        raise HttpAdapterError("HTTP_ADAPTER_FAILED")

    try:
        total_timeout = float(request["total_timeout_seconds"])
        connect_timeout = float(request["connect_timeout_seconds"])
        max_body = int(request["max_response_body_bytes"])
        url = request["url"]
        if not isinstance(url, str) or not url:
            raise HttpAdapterError("HTTP_ADAPTER_FAILED")
    except (KeyError, TypeError, ValueError):
        raise HttpAdapterError("HTTP_ADAPTER_FAILED") from None
    if total_timeout <= 0 or connect_timeout <= 0 or max_body <= 0:
        raise HttpAdapterError("HTTP_ADAPTER_FAILED")

    parsed = urllib.parse.urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise HttpAdapterError("HTTP_ADAPTER_FAILED")

    deadline = time.monotonic() + total_timeout
    ctx = ssl.create_default_context() if scheme == "https" else None
    opener = _build_production_opener(
        ctx, connect_timeout=connect_timeout, deadline=deadline, scheme=scheme
    )
    req = urllib.request.Request(
        url,
        data=None,
        headers=dict(request.get("headers") or {}),
        method=request["method"],
    )
    # Initial open timeout: remaining wall-clock (connect uses connect_timeout inside).
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise HttpAdapterError("HTTP_ADAPTER_FAILED")
        with opener.open(req, timeout=remaining) as resp:
            status = int(getattr(resp, "status", 0) or resp.getcode())
            raw_headers = {k: v for k, v in resp.headers.items()}
            body = _read_body_with_deadline(
                resp, max_body=max_body, deadline=deadline
            )
            return {"status": status, "headers": raw_headers, "body": body}
    except HttpAdapterError:
        raise
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        raw_headers = {k: v for k, v in (exc.headers or {}).items()}
        try:
            body = _read_body_with_deadline(
                exc if exc.fp else None, max_body=max_body, deadline=deadline
            )
        except HttpAdapterError:
            raise
        except Exception:
            # Timeout / OSError / any read failure must not masquerade as empty body.
            raise HttpAdapterError("HTTP_ADAPTER_FAILED") from None
        return {"status": status, "headers": raw_headers, "body": body}
    except Exception:
        raise HttpAdapterError("HTTP_ADAPTER_FAILED") from None


def execute_http(
    *,
    binding: Mapping[str, Any],
    method: str,
    path: str,
    lease: SecretLease,
    transport: Optional[TransportFn] = None,
) -> Dict[str, Any]:
    """Execute one HTTP/HTTPS request. Never accepts model host/URL/Authorization."""
    secrets_for_scrub: list[str] = []
    materials: list[tuple[str, str]] = []
    try:
        if not isinstance(binding, Mapping) or binding.get("type") != "http":
            return _safe_fail("HTTP_BINDING_INVALID")
        target = binding.get("target")
        request_cfg = binding.get("request")
        inject = binding.get("inject")
        credential_ref = binding.get("credential_ref")
        if not isinstance(target, Mapping) or not isinstance(request_cfg, Mapping):
            return _safe_fail("HTTP_BINDING_INVALID")
        if not isinstance(inject, Mapping):
            return _safe_fail("HTTP_BINDING_INVALID")
        if not isinstance(credential_ref, str) or not credential_ref:
            return _safe_fail("HTTP_BINDING_INVALID")
        scheme = target.get("scheme")
        if scheme not in {"http", "https"}:
            return _safe_fail("HTTP_BINDING_INVALID")
        host = target.get("host")
        port = target.get("port")
        if not isinstance(host, str) or not isinstance(port, int):
            return _safe_fail("HTTP_BINDING_INVALID")

        try:
            method_s = validate_http_method(method)
            path_s = _validate_relative_path(path)
        except (ValueError, HttpAdapterError):
            return _safe_fail("HTTP_REQUEST_REJECTED")

        allowed_methods = tuple(request_cfg.get("allowed_methods") or ())
        allowed_paths = tuple(request_cfg.get("allowed_paths") or ())
        if method_s not in allowed_methods or path_s not in allowed_paths:
            return _safe_fail("HTTP_REQUEST_REJECTED")

        connect_timeout = int(request_cfg.get("connect_timeout_seconds") or 5)
        total_timeout = int(request_cfg.get("total_timeout_seconds") or 30)
        max_body = int(request_cfg.get("max_response_body_bytes") or 65536)
        if connect_timeout <= 0 or total_timeout <= 0 or max_body <= 0:
            return _safe_fail("HTTP_BINDING_INVALID")

        try:
            auth_headers = _build_auth_headers(inject, lease)
        except (HttpAdapterError, InjectionError):
            return _safe_fail("HTTP_INJECT_FAILED")

        # Collect secret fragments + session materials for unified result guard.
        try:
            materials = _session_materials(credential_ref, lease)
            for _name, secret in materials:
                secrets_for_scrub.append(secret)
        except InjectionError:
            return _safe_fail("HTTP_INJECT_FAILED")

        url = f"{scheme}://{host}:{port}{path_s}"
        transport_req: Dict[str, Any] = {
            "method": method_s,
            "url": url,
            "headers": dict(auth_headers),
            "allow_redirects": False,
            "trust_env": False,
            "verify": True,
            "connect_timeout_seconds": connect_timeout,
            "total_timeout_seconds": total_timeout,
            "max_response_body_bytes": max_body,
        }

        runner = transport or _default_transport
        try:
            raw = runner(transport_req)
        except HttpAdapterError:
            return _safe_fail("HTTP_ADAPTER_FAILED")
        except Exception:
            return _safe_fail("HTTP_ADAPTER_FAILED")

        if not isinstance(raw, dict):
            return _safe_fail("HTTP_ADAPTER_FAILED")
        status = raw.get("status")
        if not isinstance(status, int) or status < 100 or status > 599:
            return _safe_fail("HTTP_ADAPTER_FAILED")

        # 3xx: return safe result without following.
        # Response headers: model-output allowlist only (not a wire parse-time limit).
        headers_in = raw.get("headers") or {}
        if not isinstance(headers_in, Mapping):
            headers_in = {}

        body = raw.get("body", b"")
        if isinstance(body, str):
            body_b = body.encode("utf-8", errors="replace")
        elif isinstance(body, (bytes, bytearray)):
            body_b = bytes(body)
        else:
            return _safe_fail("HTTP_ADAPTER_FAILED")
        truncated = len(body_b) > max_body
        if truncated:
            body_b = body_b[:max_body]

        text = body_b.decode("utf-8", errors="replace")
        text = _guard_text(text, materials)
        if text == RESULT_GUARD_FAIL_TEXT:
            return _safe_fail("HTTP_RESULT_SCRUBBED")
        body_out: Any
        try:
            body_out = json.loads(text) if text else ""
        except json.JSONDecodeError:
            body_out = text

        safe_headers = _filter_response_headers(headers_in)
        # Guard leaked decoy from header values with the same authority.
        for hk, hv in list(safe_headers.items()):
            guarded = _guard_text(hv, materials)
            if guarded == RESULT_GUARD_FAIL_TEXT:
                return _safe_fail("HTTP_RESULT_SCRUBBED")
            safe_headers[hk] = guarded

        result = {
            "ok": True,
            "status": status,
            "headers": safe_headers,
            "body": body_out,
            "truncated": truncated,
        }
        # Final belt: ensure secrets do not appear in serialized result.
        dumped = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        for secret in secrets_for_scrub:
            if secret and secret in dumped:
                return _safe_fail("HTTP_RESULT_SCRUBBED")
        return result
    except Exception:
        return _safe_fail("HTTP_ADAPTER_FAILED")


__all__ = [
    "HttpAdapterError",
    "execute_http",
]
