"""Public-looking synthetic identities; these credentials never belong to live servers."""

import base64
from datetime import datetime, timezone
import json
from types import SimpleNamespace

from sauh_network_scanner.checks.core.vpn import VPNSettings
from sauh_network_scanner.checks.domain.vpn import (
    CHECKER_VERSION,
    LatencyProbe,
    VPNSpec,
    VPNObservation,
)


UUID = "b98a6b11-14a7-44ce-81db-cb3d39a8941a"
PUBLIC_KEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")


def spec(protocol="vless", *, host="vpn.example.com", port=443, reality=False):
    if protocol == "vless":
        suffix = (
            f"security=reality&sni=vpn.example.com&pbk={PUBLIC_KEY}&sid=1234&flow=xtls-rprx-vision"
            if reality
            else "security=tls"
        )
        uri = f"vless://{UUID}@{host}:{port}?{suffix}"
    elif protocol == "vmess":
        body = dict(
            v="2",
            ps="untrusted label",
            add=host,
            port=str(port),
            id=UUID,
            aid="0",
            scy="auto",
            net="tcp",
            type="none",
            tls="tls",
        )
        uri = "vmess://" + base64.b64encode(json.dumps(body).encode()).decode()
    elif protocol == "trojan":
        uri = f"trojan://public-test-password@{host}:{port}?security=tls"
    elif protocol == "ss":
        auth = (
            base64.urlsafe_b64encode(b"aes-256-gcm:long-public-test-password")
            .decode()
            .rstrip("=")
        )
        uri = f"ss://{auth}@{host}:{port}"
    elif protocol == "hysteria2":
        uri = f"hysteria2://public-test-password@{host}:{port}?sni=vpn.example.com&alpn=h3"
    else:
        uri = f"tuic://{UUID}:public-test-password@{host}:{port}?sni=vpn.example.com&alpn=h3&congestion_control=bbr"
    return VPNSpec.from_uri(uri)


def observation(
    *,
    good=True,
    when=None,
    latency=50,
    speed=10,
    upload_speed=10,
    exit_ip="1.1.1.1",
    country="US",
):
    config = VPNSettings()
    probes = (
        [
            LatencyProbe(url=url, first_response_ms=latency, rtt_ms=[latency, latency])
            for url in config.probe_urls
        ]
        if good
        else []
    )
    return VPNObservation(
        checked_at=when or datetime.now(timezone.utc),
        checker_version=CHECKER_VERSION,
        validation_key=config.validation_key,
        health_validation_key=config.health_validation_key,
        samples=2,
        resolved_ip="8.8.8.8",
        exit_ip=exit_ip if good else None,
        country_code=country if good else None,
        first_response_ms=latency if good else None,
        latency_probes=probes,
        rtt_ms=[rtt for probe in probes for rtt in probe.rtt_ms],
        download_bytes=1048576 if good else 0,
        download_ms=1048576 * 8 / (speed * 1000) if good else None,
        upload_bytes=1048576 if good else 0,
        upload_confirmed_bytes=1048576 if good else 0,
        upload_ms=1048576 * 8 / (upload_speed * 1000) if good else None,
        upload_ok=good,
        download_ok=good,
        error=None if good else "tunnel: TimeoutError",
    )


def node(value=None, *, country="US"):
    value = value or spec()
    return SimpleNamespace(
        key=value.key,
        uri=value.uri,
        country_code=country,
        latency_ms=50,
        download_mbps=10,
        upload_mbps=5,
    )
