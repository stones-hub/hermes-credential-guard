from __future__ import annotations

import json
import os
import shutil
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Callable, List, Optional, Union


class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True


ResponseSpec = Union[dict, Callable[[dict], dict]]


class FakeProvider:
    """OpenAI-compatible fake provider for Hermes streaming/non-streaming calls."""

    def __init__(self, scripted_responses: Optional[List[ResponseSpec]] = None) -> None:
        self._lock = threading.Lock()
        self._requests: list[tuple[str, str, bytes]] = []
        self._scripted = list(scripted_responses or [])
        self._script_index = 0
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def _capture(self, body: bytes) -> None:
                with outer._lock:
                    outer._requests.append((self.command, self.path, body))

            def do_GET(self):  # noqa: N802
                self._capture(b"")
                payload = {
                    "object": "list",
                    "data": [{"id": "fake-model", "object": "model"}],
                }
                if self.path.rstrip("/").endswith("fake-model"):
                    payload = {"id": "fake-model", "object": "model"}
                self._write_json(payload)

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length)
                self._capture(body)
                if "chat/completions" not in self.path:
                    # model probe endpoints used by some local providers
                    self._write_json({"ok": True})
                    return
                try:
                    req = json.loads(body.decode("utf-8"))
                    stream = bool(req.get("stream"))
                except Exception:
                    req = {}
                    stream = False
                payload = outer._next_chat_payload(req)
                if stream:
                    self._write_sse_from_payload(payload)
                else:
                    self._write_json(payload)

            def _write_json(self, payload: dict[str, Any]) -> None:
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _write_sse_from_payload(self, payload: dict[str, Any]) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                message = (payload.get("choices") or [{}])[0].get("message") or {}
                tool_calls = message.get("tool_calls")
                content = message.get("content") or ""
                if tool_calls:
                    # OpenAI-style streamed tool_calls (index required).
                    streamed_calls = []
                    for i, tc in enumerate(tool_calls):
                        fn = tc.get("function") or {}
                        streamed_calls.append(
                            {
                                "index": i,
                                "id": tc.get("id") or f"call_{i}",
                                "type": "function",
                                "function": {
                                    "name": fn.get("name") or "",
                                    "arguments": fn.get("arguments") or "{}",
                                },
                            }
                        )
                    chunks = [
                        {
                            "id": "chatcmpl-canary",
                            "object": "chat.completion.chunk",
                            "model": "fake-model",
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {"role": "assistant", "content": None},
                                    "finish_reason": None,
                                }
                            ],
                        },
                        {
                            "id": "chatcmpl-canary",
                            "object": "chat.completion.chunk",
                            "model": "fake-model",
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {"tool_calls": streamed_calls},
                                    "finish_reason": None,
                                }
                            ],
                        },
                        {
                            "id": "chatcmpl-canary",
                            "object": "chat.completion.chunk",
                            "model": "fake-model",
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {},
                                    "finish_reason": "tool_calls",
                                }
                            ],
                        },
                    ]
                else:
                    chunks = [
                        {
                            "id": "chatcmpl-canary",
                            "object": "chat.completion.chunk",
                            "model": "fake-model",
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {"role": "assistant", "content": ""},
                                    "finish_reason": None,
                                }
                            ],
                        },
                        {
                            "id": "chatcmpl-canary",
                            "object": "chat.completion.chunk",
                            "model": "fake-model",
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {"content": content or "ok"},
                                    "finish_reason": None,
                                }
                            ],
                        },
                        {
                            "id": "chatcmpl-canary",
                            "object": "chat.completion.chunk",
                            "model": "fake-model",
                            "choices": [
                                {
                                    "index": 0,
                                    "delta": {},
                                    "finish_reason": "stop",
                                }
                            ],
                        },
                    ]
                for chunk in chunks:
                    self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode("utf-8"))
                    self.wfile.flush()
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

            def log_message(self, format: str, *args: Any) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def _default_payload(self) -> dict[str, Any]:
        return {
            "id": "chatcmpl-canary",
            "object": "chat.completion",
            "model": "fake-model",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "ok"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {
                "prompt_tokens": 1,
                "completion_tokens": 1,
                "total_tokens": 2,
            },
        }

    def _next_chat_payload(self, req: dict) -> dict[str, Any]:
        with self._lock:
            if self._script_index < len(self._scripted):
                spec = self._scripted[self._script_index]
                self._script_index += 1
            else:
                spec = None
        if spec is None:
            return self._default_payload()
        if callable(spec):
            return spec(req)
        return spec

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}/v1"

    @property
    def requests(self) -> list[tuple[str, str, bytes]]:
        with self._lock:
            return list(self._requests)

    @property
    def captured_bodies(self) -> list[str]:
        return [body.decode("utf-8", "replace") for _, _, body in self.requests if body]

    @property
    def chat_completion_bodies(self) -> list[bytes]:
        out = []
        for method, path, body in self.requests:
            if method == "POST" and "chat/completions" in path:
                out.append(body)
        return out

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def tool_call_response(name: str, arguments: dict, call_id: str = "call_m2_1") -> dict:
    return {
        "id": "chatcmpl-canary",
        "object": "chat.completion",
        "model": "fake-model",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": json.dumps(arguments),
                            },
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


def text_response(content: str = "done") -> dict:
    return {
        "id": "chatcmpl-canary",
        "object": "chat.completion",
        "model": "fake-model",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }
