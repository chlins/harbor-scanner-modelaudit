"""Entry point."""

from __future__ import annotations

import logging

import uvicorn

from scanner.api.app import create_app
from scanner.config import settings


def run() -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    uvicorn.run(
        create_app(settings),
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        timeout_keep_alive=settings.api_server_read_timeout,
    )


if __name__ == "__main__":
    run()
