"""Public CLI; all configuration is device-local and contains only its own key."""

import argparse
import asyncio
import getpass
import json
import logging
import os
from pathlib import Path
import platform
import re
import signal
import sqlite3
import sys

import yaml

from . import __version__
from .autostart import definition
from .config import Settings, load_settings
from .install import install_core
from .runtime import Runtime
from .storage import DeviceLock, Outbox, private_path


def configure(path, api_url):
    path = path.expanduser().resolve()
    settings = Settings(api_url=api_url)
    key = getpass.getpass(
        "Your scanner API_KEY (provided by the administrator): "
    ).strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{32,512}", key):
        raise ValueError("API_KEY must have 32..512 non-space characters")
    path.parent.mkdir(parents=True, exist_ok=True)
    credential = path.parent / settings.API_KEY_FILE
    credential.write_text(json.dumps({"API_KEY": key}))
    private_path(credential)
    path.write_text(
        yaml.safe_dump(
            settings.model_dump(mode="json", exclude={"API_KEY", "API_KEY_ENV"}),
            sort_keys=False,
        )
    )
    private_path(path)
    print("Device configuration saved. No credentials are printed.")


async def run(settings, duration=None):
    directory = Path(settings.state_directory)
    private_path(directory, directory=True)
    with DeviceLock(directory / "agent.lock"):
        outbox = Outbox(directory)
        runtime = Runtime(settings, outbox)
        loop = asyncio.get_running_loop()
        if os.name != "nt":
            for sig in (signal.SIGINT, signal.SIGTERM):
                loop.add_signal_handler(sig, runtime.stop.set)

        async def stop_after():
            await asyncio.sleep(duration)
            runtime.stop.set()

        timer = asyncio.create_task(stop_after()) if duration else None
        try:
            await runtime.run()
        finally:
            if timer:
                timer.cancel()
                await asyncio.gather(timer, return_exceptions=True)
            outbox.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("scanner.yaml"))
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("configure")
    setup.add_argument("--api-url", default="https://api.kauliki.ru")
    commands.add_parser("validate-config")
    commands.add_parser("status")
    installation = commands.add_parser("install-core")
    installation.add_argument("--version", default="1.14.4")
    startup = commands.add_parser("autostart")
    startup.add_argument("--output", type=Path, required=True)
    startup.add_argument(
        "--platform",
        choices=["windows", "linux", "darwin"],
        default=platform.system().lower(),
    )
    scan = commands.add_parser("run")
    scan.add_argument(
        "--duration", type=float, help="Optional bounded diagnostic run in seconds"
    )
    args = parser.parse_args()
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    # Third-party probe exception strings can contain target credentials; only
    # controlled runtime summaries are sent to stdout or central logs.
    for name in ("kauliki_network_scanner.checks", "aiohttp", "asyncio"):
        logging.getLogger(name).setLevel(logging.CRITICAL)
    try:
        if args.command == "configure":
            configure(args.config, args.api_url)
            return 0
        settings = load_settings(args.config)
        if args.command == "validate-config":
            settings.credential()
            print("Device configuration valid; API_KEY is not printed.")
        elif args.command == "install-core":
            asyncio.run(install_core(settings.core_path, args.version))
            print("Verified sing-box core installed.")
        elif args.command == "autostart":
            text = definition(args.platform, args.config)
            args.output.write_text(
                text, encoding="utf-16" if args.platform == "windows" else "utf-8"
            )
            print("User autostart definition saved; see README for installation.")
        elif args.command == "status":
            database = Path(settings.state_directory) / "outbox.sqlite3"
            if not database.is_file():
                print("No local measurements yet.")
            else:
                with sqlite3.connect(
                    database.as_uri() + "?mode=ro", uri=True
                ) as connection:
                    print(
                        "Pending observations:",
                        connection.execute("SELECT count(*) FROM results").fetchone()[
                            0
                        ],
                    )
        else:
            settings.credential()
            if args.duration is not None and args.duration <= 0:
                raise ValueError("duration must be positive")
            asyncio.run(run(settings, args.duration))
    except KeyboardInterrupt:
        return 0
    except (ValueError, OSError, sqlite3.Error) as exc:
        print(
            f"Scanner cannot start: {type(exc).__name__}. Check configuration and README.",
            file=sys.stderr,
        )
        return 1
    return 0
