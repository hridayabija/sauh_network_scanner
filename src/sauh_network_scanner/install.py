"""Explicit pinned installation with published SHA256, including Windows ZIP."""

import asyncio
import hashlib
import json
import os
from pathlib import Path
import platform
import tarfile
import tempfile
import zipfile

import aiohttp


async def install_core(destination, version="1.14.4"):
    manifest = json.loads(Path(__file__).with_name("core-releases.json").read_text())
    system = platform.system().lower()
    arch = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(platform.machine().lower())
    extension = "zip" if system == "windows" else "tar.gz"
    name = f"sing-box-{version}-{system}-{arch}.{extension}"
    asset = manifest.get(version, {}).get(name)
    if asset is None:
        raise ValueError(
            "No reviewed release for this platform/version; install sing-box manually"
        )
    if not asset["url"].startswith(
        f"https://github.com/SagerNet/sing-box/releases/download/v{version}/"
    ):
        raise ValueError("Unexpected release source")
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    binary_name = "sing-box.exe" if system == "windows" else "sing-box"
    with tempfile.TemporaryDirectory(dir=destination.parent) as directory:
        archive = Path(directory) / name
        async with aiohttp.ClientSession(
            trust_env=False, timeout=aiohttp.ClientTimeout(total=180)
        ) as session:
            async with session.get(asset["url"]) as response:
                response.raise_for_status()
                checksum, size = hashlib.sha256(), 0
                with archive.open("wb") as output:
                    async for block in response.content.iter_chunked(1024 * 1024):
                        size += len(block)
                        if size > 128 * 1024 * 1024:
                            raise ValueError("Core archive exceeds size limit")
                        checksum.update(block)
                        output.write(block)
        if checksum.hexdigest() != asset["sha256"]:
            raise ValueError("Core checksum mismatch")
        binary = Path(directory) / binary_name
        if extension == "zip":
            with zipfile.ZipFile(archive) as bundle:
                members = [
                    info
                    for info in bundle.infolist()
                    if info.filename.endswith("/" + binary_name) and not info.is_dir()
                ]
                if len(members) != 1 or members[0].file_size > 256 * 1024 * 1024:
                    raise ValueError("Invalid core archive")
                with bundle.open(members[0]) as source, binary.open("wb") as output:
                    while block := source.read(1024 * 1024):
                        output.write(block)
        else:
            with tarfile.open(archive) as bundle:
                members = [
                    info
                    for info in bundle.getmembers()
                    if info.isfile() and info.name.endswith("/" + binary_name)
                ]
                if len(members) != 1 or members[0].size > 256 * 1024 * 1024:
                    raise ValueError("Invalid core archive")
                with (
                    bundle.extractfile(members[0]) as source,
                    binary.open("wb") as output,
                ):
                    while block := source.read(1024 * 1024):
                        output.write(block)
        binary.chmod(0o755)
        os.replace(binary, destination)
    return destination
