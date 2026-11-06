"""Start the AegisClick API on a single dual-stack TCP socket.

`uvicorn --host 0.0.0.0` binds IPv4 only. On Windows `localhost` resolves to
`::1` (AAAA) before `127.0.0.1` (A), so a browser can end up refusing the
connection even though the server is healthy. Binding one AF_INET6 socket with
`IPV6_V6ONLY=0` accepts both IPv6 and IPv4 clients on the same port.

Env: HOST (default "::"), PORT (default 8000), LOG_LEVEL (default "info").
"""
from __future__ import annotations

import os
import socket

import uvicorn

HOST = os.environ.get("HOST", "::")
PORT = int(os.environ.get("PORT", "8000"))


def main() -> None:
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    except (AttributeError, OSError):
        pass
    sock.bind((HOST, PORT))
    sock.listen(2048)

    config = uvicorn.Config(
        "aegis.api.app:app_factory",
        factory=True,
        host=HOST,
        port=PORT,
        log_level=os.environ.get("LOG_LEVEL", "info"),
    )
    uvicorn.Server(config).run(sockets=[sock])


if __name__ == "__main__":
    main()
