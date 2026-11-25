"""Rotating local diagnostics; probe libraries cannot print credentials."""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from .storage import private_path


def configure_logging(settings):
    directory = Path(settings.state_directory)
    private_path(directory, directory=True)
    path = directory / "scanner.log"
    handler = RotatingFileHandler(
        path, maxBytes=settings.log_max_bytes, backupCount=settings.log_backups, encoding="utf-8"
    )
    private_path(path)

    # Only controlled runtime events are admitted to stdout and files.
    def controlled(record):
        return record.name == "sauh_network_scanner.runtime"

    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    for output in (handler, logging.StreamHandler()):
        output.setFormatter(formatter)
        output.addFilter(controlled)
        logger = logging.getLogger("sauh_network_scanner.runtime")
        logger.addHandler(output)
    logger.setLevel(settings.log_level)
    logger.propagate = False
    for name in ("sauh_network_scanner.checks", "aiohttp", "asyncio"):
        library = logging.getLogger(name)
        library.setLevel(logging.CRITICAL)
        library.addHandler(logging.NullHandler())
        library.propagate = False
