#!/usr/bin/env python3
"""Process-level loopback-only network guard, then run the Hermes CLI.

Guards Python socket *conventional* outbound entry points:
  - socket.socket.connect
  - socket.socket.connect_ex
  - socket.create_connection
  - socket.socket.sendto
  - socket.socket.sendmsg (when the platform provides it)

Only loopback IPv4/IPv6 (and localhost) IP peers are allowed. AF_UNIX is left
alone. Every IP attempt is audited before any network I/O.

This is NOT an OS sandbox: raw libc connect via ctypes/cffi, subprocess tools
(curl/nc), and other interpreters are outside this guard. Stronger isolation
requires container/OS network policy.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any, Callable, List, Optional, Tuple


_ATTEMPTS: List[Tuple[str, int]] = []
_AUDIT_PATH = os.environ.get("CREDENTIAL_GUARD_NET_AUDIT_PATH", "").strip()
# Optional precise allowlist: "127.0.0.1:1234,127.0.0.1:5678". When set,
# loopback peers not on the list are recorded and rejected (AF_UNIX exempt).
_ALLOW_SPEC = os.environ.get("CREDENTIAL_GUARD_NET_ALLOWLIST", "").strip()

# Documentation / test-only addresses that must never leave the host.
DOCUMENTATION_BLOCK_HOSTS = frozenset(
    {
        "203.0.113.1",  # TEST-NET-3 (RFC 5737)
        "2001:db8::1",  # documentation prefix (RFC 3849)
    }
)

GUARDED_ENTRYPOINTS = (
    "socket.socket.connect",
    "socket.socket.connect_ex",
    "socket.create_connection",
    "socket.socket.sendto",
    "socket.socket.sendmsg",
)


def _is_loopback_host(host: str) -> bool:
    if not host:
        return False
    h = host.strip().lower().strip("[]")
    if h in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _parse_ip_address(address: Any) -> Optional[Tuple[str, int]]:
    """Parse IP peer from connect/sendto-style address; None for AF_UNIX etc."""
    if isinstance(address, tuple) and address:
        host = address[0]
        port = int(address[1]) if len(address) > 1 else 0
        if isinstance(host, bytes):
            host = host.decode("utf-8", "replace")
        if isinstance(host, str):
            # AF_UNIX addresses are path strings passed as a bare str to connect,
            # not (host, port) tuples — so a str host here is treated as IP peer.
            return str(host), port
    return None


def _record(host: str, port: int) -> None:
    _ATTEMPTS.append((str(host), int(port)))
    if _AUDIT_PATH:
        try:
            Path(_AUDIT_PATH).write_text(
                json.dumps({"attempts": _ATTEMPTS}, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError:
            pass


def _reject(host: str, port: int, kind: str) -> None:
    raise OSError(
        f"credential-guard net guard blocked non-loopback {kind} to {host!r}:{port}"
    )


def _allowed_loopback_peers() -> Optional[set]:
    if not _ALLOW_SPEC:
        return None
    out = set()
    for part in _ALLOW_SPEC.split(","):
        part = part.strip()
        if not part or ":" not in part:
            continue
        host, port_s = part.rsplit(":", 1)
        try:
            out.add((host.strip().lower().strip("[]"), int(port_s)))
        except ValueError:
            continue
    return out


def _check_peer(address: Any, kind: str) -> Optional[Tuple[str, int]]:
    parsed = _parse_ip_address(address)
    if parsed is None:
        return None
    host, port = parsed
    _record(host, port)
    if not _is_loopback_host(host):
        _reject(host, port, kind)
    allow = _allowed_loopback_peers()
    if allow is not None:
        key = (str(host).strip().lower().strip("[]"), int(port))
        # Also accept localhost alias forms for 127.0.0.1 allow entries.
        aliases = {key}
        if key[0] in {"127.0.0.1", "localhost"}:
            aliases.add(("127.0.0.1", key[1]))
            aliases.add(("localhost", key[1]))
        if not aliases.intersection(allow):
            raise OSError(
                f"credential-guard net guard blocked non-allowlisted "
                f"loopback {kind} to {host!r}:{port}"
            )
    return parsed


_ORIG_CONNECT = socket.socket.connect
_ORIG_CONNECT_EX = socket.socket.connect_ex
_ORIG_CREATE_CONNECTION = socket.create_connection
_ORIG_SENDTO = socket.socket.sendto
_ORIG_SENDMSG: Optional[Callable[..., Any]] = getattr(socket.socket, "sendmsg", None)


def _guard_connect(self, address):  # noqa: ANN001
    if _check_peer(address, "connect") is None:
        return _ORIG_CONNECT(self, address)
    return _ORIG_CONNECT(self, address)


def _guard_connect_ex(self, address):  # noqa: ANN001
    import errno as errno_mod

    try:
        if _check_peer(address, "connect_ex") is None:
            return _ORIG_CONNECT_EX(self, address)
    except OSError as exc:
        # connect_ex normally returns errno; map guard refusal to EPERM.
        return getattr(exc, "errno", None) or errno_mod.EPERM
    return _ORIG_CONNECT_EX(self, address)


def _guard_create_connection(address, *args, **kwargs):  # noqa: ANN001
    _check_peer(address, "create_connection")
    return _ORIG_CREATE_CONNECTION(address, *args, **kwargs)


def _guard_sendto(self, data, *args, **kwargs):  # noqa: ANN001
    # sendto(data[, flags], address)  OR  sendto(data, address)
    address = None
    if args:
        address = args[-1] if not isinstance(args[-1], int) else kwargs.get("address")
    if address is None:
        address = kwargs.get("address")
    if address is not None:
        _check_peer(address, "sendto")
    return _ORIG_SENDTO(self, data, *args, **kwargs)


def _guard_sendmsg(self, buffers, ancdata=None, flags=0, address=None):  # noqa: ANN001
    if address is not None:
        _check_peer(address, "sendmsg")
    assert _ORIG_SENDMSG is not None
    # Native sendmsg rejects ancdata=None (not iterable). Match CPython's
    # default when the caller omits ancdata: treat None as empty.
    if ancdata is None:
        ancdata = []
    return _ORIG_SENDMSG(self, buffers, ancdata, flags, address)


def install_guards() -> None:
    socket.socket.connect = _guard_connect  # type: ignore[method-assign]
    socket.socket.connect_ex = _guard_connect_ex  # type: ignore[method-assign]
    socket.create_connection = _guard_create_connection  # type: ignore[assignment]
    socket.socket.sendto = _guard_sendto  # type: ignore[method-assign]
    if _ORIG_SENDMSG is not None:
        socket.socket.sendmsg = _guard_sendmsg  # type: ignore[method-assign]


def assert_guards_installed() -> None:
    """Fail if any guarded entry point is not the installed wrapper."""
    assert socket.socket.connect is _guard_connect, "connect guard missing"
    assert socket.socket.connect_ex is _guard_connect_ex, "connect_ex guard missing"
    assert socket.create_connection is _guard_create_connection, (
        "create_connection guard missing"
    )
    assert socket.socket.sendto is _guard_sendto, "sendto guard missing"
    if _ORIG_SENDMSG is not None:
        assert socket.socket.sendmsg is _guard_sendmsg, "sendmsg guard missing"


def remaining_bypass_notes() -> List[str]:
    return [
        "ctypes/cffi direct libc connect/sendto/sendmsg syscalls",
        "subprocess invoking curl/wget/nc/openssl s_client",
        "other language runtimes spawned as child processes",
        "kernel-bypass / raw packet APIs if present",
    ]


def main(argv=None) -> int:
    install_guards()
    assert_guards_installed()
    hermes_bin = os.environ.get(
        "CREDENTIAL_GUARD_HERMES_BIN",
        "/Users/yelei/.hermes/hermes-agent/venv/bin/hermes",
    )
    sys.argv = ["hermes", *(argv if argv is not None else sys.argv[1:])]
    agent_root = Path(hermes_bin).resolve().parents[2]
    if str(agent_root) not in sys.path:
        sys.path.insert(0, str(agent_root))
    from hermes_cli.main import main as hermes_main

    result = hermes_main()
    return int(result or 0)


if __name__ == "__main__":
    raise SystemExit(main())
