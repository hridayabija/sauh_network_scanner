"""Canonical subscription identities and a strict, transport-aware security policy."""

import base64
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
import re
from statistics import median
from typing import Annotated, Literal
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator

from sauh_network_scanner.checks.domain.mtproxy import (
    HISTORY_WINDOW,
    country_flag,
    normalize_host,
)


PROTOCOL_LABELS = {
    "vless": "VLESS",
    "vmess": "VMess",
    "trojan": "Trojan",
    "ss": "Shadowsocks",
    "hysteria2": "Hysteria2",
    "tuic": "TUIC",
}
SS_METHODS = {
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
FINGERPRINTS = {"chrome", "firefox", "safari", "ios", "edge", "random", "randomized"}
CLIENT_FINGERPRINT = "firefox"
TLS_AEAD_SUITES = [
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
]
TRANSPORTS = {"tcp", "ws", "grpc", "http", "httpupgrade"}
TLS_QUERY = {
    "security",
    "sni",
    "peer",
    "allowInsecure",
    "insecure",
    "skip-cert-verify",
    "fp",
    "alpn",
}
TRANSPORT_QUERY = {
    "type",
    "headerType",
    "host",
    "path",
    "serviceName",
    "mode",
    "ed",
    "eh",
}
METADATA_QUERY = {"remarks", "remark", "name", "ps"}
CHECKER_VERSION = 4
# Version 2 already verified TLS and acknowledged upload. Its full successes
# remain trustworthy when upgrading the availability/quality policy.
MIN_VALIDATED_CHECKER_VERSION = 2


class ConfigRejected(ValueError):
    """A reason code, deliberately containing no source credentials."""


def reject(reason):
    raise ConfigRejected(reason)


def decode64(value):
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, UnicodeError):
        reject("invalid_base64")


def public_host(value):
    host = normalize_host(value)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    if not address.is_global:
        reject("non_public_server")
    return host


def dns_name(value):
    host = normalize_host(value)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    reject("tls_server_name_required")


def uuid(value):
    try:
        return str(UUID(value))
    except (ValueError, TypeError, AttributeError):
        reject("invalid_uuid")


def text(value, *, limit=2048):
    if (
        not isinstance(value, str)
        or len(value) > limit
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        reject("invalid_field")
    return value


def boolean(value):
    if value in (False, 0, "0", "false", "False", ""):
        return False
    if value in (True, 1, "1", "true", "True"):
        return True
    reject("invalid_boolean")


def query(parts, allowed):
    values = parse_qs(parts.query, keep_blank_values=True, max_num_fields=50)
    if any(len(items) != 1 for items in values.values()):
        reject("duplicate_parameters")
    if set(values) - allowed - METADATA_QUERY:
        reject("unsupported_parameters")
    values = {
        key: text(items[0])
        for key, items in values.items()
        if key not in METADATA_QUERY
    }
    for key in ("allowInsecure", "insecure", "skip-cert-verify"):
        if key in values and boolean(values[key]):
            reject("certificate_verification_disabled")
    return values


def address(parts, *, default_port=None):
    if not parts.hostname:
        reject("invalid_server")
    host = public_host(parts.hostname)
    port = parts.port if parts.port is not None else default_port
    if port is None or not 1 <= port <= 65535:
        reject("invalid_port")
    return host, port


def authority(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def transport(values, *, fallback="tcp"):
    kind = values.get("type", fallback) or fallback
    kind = {"raw": "tcp", "h2": "http"}.get(kind, kind)
    if kind not in TRANSPORTS:
        reject("unsupported_transport")
    if values.get("headerType", "none") not in {"", "none"}:
        reject("unsupported_tcp_header")
    result, canonical = {}, {"type": kind}
    if kind == "tcp":
        if any(
            values.get(field)
            for field in ("path", "host", "serviceName", "ed", "eh", "mode")
        ):
            reject("unexpected_tcp_transport_fields")
        return kind, result, canonical
    result["type"] = kind
    if kind == "grpc":
        if values.get("mode", "gun") not in {"", "gun"}:
            reject("unsupported_grpc_mode")
        service = values.get("serviceName", "")
        if any(values.get(field) for field in ("path", "host", "ed", "eh")):
            reject("unexpected_grpc_transport_fields")
        if service:
            result["service_name"], canonical["serviceName"] = service, service
        return kind, result, canonical
    path = values.get("path") or "/"
    if not path.startswith("/"):
        reject("invalid_transport_path")
    result["path"], canonical["path"] = path, path
    host = values.get("host")
    if host:
        # A Host header is data, never a URL, command or user-selected destination.
        host = dns_name(host)
        canonical["host"] = host
        if kind == "ws":
            result["headers"] = {"Host": host}
        else:
            result["host"] = [host] if kind == "http" else host
    if values.get("serviceName") or values.get("mode"):
        reject("unexpected_transport_fields")
    if values.get("ed") or values.get("eh"):
        if kind != "ws":
            reject("unsupported_early_data")
        size = int(values.get("ed", "0"))
        if not 0 <= size <= 4096:
            reject("invalid_early_data")
        header = values.get("eh") or "Sec-WebSocket-Protocol"
        if not re.fullmatch(r"[A-Za-z0-9-]{1,100}", header):
            reject("invalid_early_data_header")
        result.update(max_early_data=size, early_data_header_name=header)
        canonical.update(ed=str(size), eh=header)
    return kind, result, canonical


def tls(values, host, *, reality=False, quic=False):
    for key in ("allowInsecure", "insecure", "skip-cert-verify"):
        if key in values and boolean(values[key]):
            reject("certificate_verification_disabled")
    sni = dns_name(values.get("sni") or values.get("peer") or host)
    if values.get("sni") and values.get("peer") and dns_name(values["peer"]) != sni:
        reject("conflicting_server_names")
    result = {
        "enabled": True,
        "server_name": sni,
        "insecure": False,
        "min_version": "1.3" if reality or quic else "1.2",
    }
    canonical = {"sni": sni}
    alpn = [item.strip() for item in values.get("alpn", "").split(",") if item.strip()]
    if len(alpn) != len(set(alpn)) or any(
        item not in {"h2", "http/1.1", "h3"} for item in alpn
    ):
        reject("unsupported_alpn")
    if alpn:
        result["alpn"], canonical["alpn"] = alpn, ",".join(alpn)
    fp = values.get("fp")
    if fp and (quic or fp not in FINGERPRINTS):
        reject("unsupported_tls_fingerprint")
    if not quic:
        # A browser preset is a client choice, not a server credential. Normalize
        # before hashing so source variants share one inventory identity.
        result["utls"] = {"enabled": True, "fingerprint": CLIENT_FINGERPRINT}
        # uTLS presets may override these options: the checker also gates the
        # actual ServerHello through a transparent authenticated TLS audit relay.
        # Firefox supports TLS 1.2. REALITY still requires 1.3; the audit relay
        # independently requires ECDHE/AEAD for an ordinary TLS 1.2 session.
        canonical["fp"] = CLIENT_FINGERPRINT
    if reality:
        pbk = values.get("pbk", "")
        if (
            not re.fullmatch(r"[A-Za-z0-9_-]{43}=?", pbk)
            or len(decode64(pbk)) != 32
            or not any(decode64(pbk))
        ):
            reject("invalid_reality_public_key")
        pbk = base64.urlsafe_b64encode(decode64(pbk)).decode().rstrip("=")
        sid = values.get("sid", "").lower()
        if len(sid) > 16 or len(sid) % 2 or not re.fullmatch(r"[0-9a-f]*", sid):
            reject("invalid_reality_short_id")
        if values.get("spx", "/") not in {"", "/"}:
            reject("unsupported_reality_spider_path")
        result["reality"] = {"enabled": True, "public_key": pbk, "short_id": sid}
        canonical.update(pbk=pbk, sid=sid)
    return result, canonical


@dataclass(frozen=True, repr=False)
class VPNSpec:
    protocol: str
    host: str
    port: int
    uri: str
    outbound: dict
    encryption: str
    transport: str

    @property
    def key(self):
        # Names are excluded; TLS keys, SNI and transport paths remain part of identity.
        identity = self.outbound
        secure = identity.get("tls", {})
        if secure.get("utls", {}).get("fingerprint") == CLIENT_FINGERPRINT:
            # A minimum version is validation policy, not a server credential.
            # Keep the established Firefox hash representation so allowing TLS
            # 1.2 does not rekey nodes or discard valid TLS 1.3 observations.
            identity = {**identity, "tls": {**secure, "min_version": "1.3"}}
        return hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def __repr__(self):
        return (
            f"VPNSpec({self.protocol}, {self.host}, {self.port}, key={self.key[:12]})"
        )

    def named_uri(self, name):
        if self.protocol == "vmess":
            value = json.loads(decode64(self.uri[8:]))
            value["ps"] = name
            return (
                "vmess://"
                + base64.b64encode(
                    json.dumps(
                        value, separators=(",", ":"), ensure_ascii=False
                    ).encode()
                ).decode()
            )
        return self.uri + "#" + quote(name, safe="")

    def pinned(self, resolved_ip):
        """An export-only configuration using the entry IP actually checked.

        Keep TLS identity and the original HTTP virtual host when bypassing DNS.
        This derived identity must never be written back to the inventory.
        """
        try:
            address = str(ipaddress.ip_address(resolved_ip))
        except (ValueError, TypeError):
            reject("invalid_validated_ip")
        public_host(address)
        if address == self.host:
            return self
        stream = self.outbound.get("transport", {})
        needs_host = (
            self.transport in {"ws", "http", "httpupgrade"}
            and not stream.get("host")
            and not stream.get("headers", {}).get("Host")
        )
        if self.protocol == "vmess":
            value = json.loads(decode64(self.uri[8:]))
            value["add"] = address
            if needs_host:
                value["host"] = self.host
            uri = (
                "vmess://"
                + base64.b64encode(
                    json.dumps(value, separators=(",", ":")).encode()
                ).decode()
            )
        else:
            parts = urlsplit(self.uri)
            params = parse_qs(parts.query, keep_blank_values=True)
            if needs_host:
                params["host"] = [self.host]
            uri = parts._replace(
                netloc=parts.netloc.rsplit("@", 1)[0]
                + "@"
                + authority(address, self.port),
                query=urlencode(params, doseq=True),
            ).geturl()
        return VPNSpec.from_uri(uri)

    @classmethod
    def from_uri(cls, uri):
        try:
            uri = uri.strip()
            if len(uri) > 16384 or not uri:
                reject("invalid_uri_length")
            if uri.lower().startswith("vmess://"):
                return parse_vmess(uri)
            if uri.lower().startswith("ss://"):
                legacy = uri[5:].split("#", 1)[0].split("?", 1)[0]
                if "@" not in legacy:
                    # Retain the query so legacy links cannot bypass plugin or
                    # unknown-option rejection during base64 normalization.
                    uri = "ss://" + decode64(legacy).decode() + uri[5 + len(legacy) :]
            parts = urlsplit(uri)
            if parts.path not in {"", "/"}:
                reject("unexpected_uri_path")
            if parts.scheme in {"vless", "trojan"}:
                return parse_stream(parts)
            if parts.scheme == "ss":
                return parse_ss(parts)
            if parts.scheme in {"hy2", "hysteria2", "tuic"}:
                return parse_quic(parts)
            reject("unsupported_protocol")
        except ConfigRejected:
            raise
        except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
            reject("malformed_configuration")


def make_spec(protocol, host, port, auth, params, outbound, encryption, kind):
    outbound.update(
        type="shadowsocks" if protocol == "ss" else protocol,
        server=host,
        server_port=port,
    )
    uri = f"{protocol}://{auth}@{authority(host, port)}"
    if params:
        uri += "?" + urlencode(sorted(params.items()))
    return VPNSpec(protocol, host, port, uri, outbound, encryption, kind)


def parse_stream(parts):
    protocol = parts.scheme
    allowed = (
        TLS_QUERY
        | TRANSPORT_QUERY
        | {"encryption", "pbk", "sid", "flow", "spx", "packetEncoding"}
    )
    values = query(parts, allowed)
    host, port = address(parts)
    if parts.password is not None or not parts.username:
        reject("invalid_authentication")
    security = values.get("security") or ("tls" if protocol == "trojan" else "")
    if security not in ({"tls", "reality"} if protocol == "vless" else {"tls"}):
        reject("encrypted_transport_required")
    kind, stream, params = transport(values)
    secure, tls_params = tls(values, host, reality=security == "reality")
    params.update(tls_params, security=security)
    outbound = {"tls": secure}
    if stream:
        outbound["transport"] = stream
    if protocol == "vless":
        if values.get("encryption", "none") != "none":
            reject("unsupported_vless_encryption")
        identity = uuid(unquote(parts.username))
        outbound["uuid"], params["encryption"] = identity, "none"
        flow = values.get("flow", "")
        if flow:
            if flow != "xtls-rprx-vision" or kind != "tcp":
                reject("unsupported_vless_flow")
            outbound["flow"], params["flow"] = flow, flow
        packet = values.get("packetEncoding")
        if packet:
            if packet not in {"xudp", "packetaddr"}:
                reject("unsupported_packet_encoding")
            outbound["packet_encoding"], params["packetEncoding"] = packet, packet
        auth = identity
    else:
        if any(
            values.get(field)
            for field in ("pbk", "sid", "flow", "encryption", "packetEncoding", "spx")
        ):
            reject("unexpected_trojan_fields")
        password = text(unquote(parts.username))
        if not password:
            reject("invalid_authentication")
        outbound["password"], auth = password, quote(password, safe="")
    if security == "tls" and any(values.get(field) for field in ("pbk", "sid", "spx")):
        reject("unexpected_reality_fields")
    return make_spec(
        protocol,
        host,
        port,
        auth,
        params,
        outbound,
        "REALITY / TLS 1.3" if security == "reality" else "TLS 1.2+",
        kind,
    )


def parse_vmess(uri):
    # The widely used v2rayN JSON share format. Legacy non-AEAD VMess is rejected.
    encoded = uri[8:].split("#", 1)[0]
    value = json.loads(decode64(encoded))
    if not isinstance(value, dict):
        reject("invalid_vmess_json")
    allowed = {
        "v",
        "ps",
        "add",
        "port",
        "id",
        "aid",
        "scy",
        "net",
        "type",
        "host",
        "path",
        "tls",
        "sni",
        "alpn",
        "fp",
        "allowInsecure",
        "insecure",
        "skip-cert-verify",
    }
    if set(value) - allowed:
        reject("unsupported_vmess_fields")
    if str(value.get("aid", "0")) != "0":
        reject("legacy_vmess_authentication")
    cipher = value.get("scy", "auto") or "auto"
    if cipher not in {"auto", "aes-128-gcm", "chacha20-poly1305"}:
        reject("weak_vmess_cipher")
    if value.get("tls") != "tls":
        reject("encrypted_transport_required")
    host, port, identity = (
        public_host(value["add"]),
        int(value["port"]),
        uuid(value["id"]),
    )
    if not 1 <= port <= 65535:
        reject("invalid_port")
    values = {
        key: text(value[key])
        for key in ("sni", "alpn", "fp", "host", "path")
        if value.get(key)
    }
    for field in ("allowInsecure", "insecure", "skip-cert-verify"):
        if field in value and boolean(value[field]):
            reject("certificate_verification_disabled")
    net = value.get("net", "tcp")
    values.update(type=net, headerType=value.get("type", "none") or "none")
    if net == "grpc":
        values["serviceName"] = values.pop("path", "")
    kind, stream, _ = transport(values)
    secure, tls_params = tls(values, host)
    outbound = {"uuid": identity, "security": cipher, "alter_id": 0, "tls": secure}
    if stream:
        outbound["transport"] = stream
    outbound.update(type="vmess", server=host, server_port=port)
    canonical = {
        "v": "2",
        "add": host,
        "port": str(port),
        "id": identity,
        "aid": "0",
        "scy": cipher,
        "net": "h2" if kind == "http" else kind,
        "type": "none",
        "tls": "tls",
        **tls_params,
    }
    for key in ("host", "path"):
        if values.get(key):
            canonical[key] = values[key]
    if kind == "grpc":
        canonical["path"] = values.get("serviceName", "")
    encoded = base64.b64encode(
        json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    return VPNSpec(
        "vmess",
        host,
        port,
        "vmess://" + encoded,
        outbound,
        f"VMess AEAD ({cipher}) / TLS 1.2+",
        kind,
    )


def parse_ss(parts):
    values = query(parts, {"plugin"})
    if values.get("plugin"):
        reject("unsupported_shadowsocks_plugin")
    if "@" not in parts.netloc:
        decoded = decode64(parts.netloc).decode()
        return parse_ss(urlsplit("ss://" + decoded))
    host, port = address(parts)
    if parts.password is None:
        auth = decode64(unquote(parts.username or "")).decode()
        method, separator, password = auth.partition(":")
        if not separator:
            reject("invalid_authentication")
    else:
        method, password = unquote(parts.username), unquote(parts.password)
    if method not in SS_METHODS:
        reject("weak_shadowsocks_cipher")
    password = text(password)
    if method.startswith("2022-"):
        length = 16 if "aes-128" in method else 32
        if any(
            len(decode64(key)) != length or not any(decode64(key))
            for key in password.split(":")
        ):
            reject("invalid_shadowsocks_2022_key")
    elif len(password.encode()) < 16:
        reject("weak_shadowsocks_password")
    auth = (
        base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
    )
    return make_spec(
        "ss",
        host,
        port,
        auth,
        {},
        {"method": method, "password": password},
        f"AEAD ({method})",
        "tcp",
    )


def parse_quic(parts):
    protocol = "tuic" if parts.scheme == "tuic" else "hysteria2"
    allowed = TLS_QUERY | {
        "obfs",
        "obfs-password",
        "obfsPassword",
        "upmbps",
        "downmbps",
        "congestion_control",
        "udp_relay_mode",
        "zero_rtt_handshake",
        "disable_sni",
    }
    values = query(parts, allowed)
    host, port = address(parts, default_port=443)
    if values.get("security", "tls") != "tls" or boolean(
        values.get("disable_sni", "0")
    ):
        reject("encrypted_transport_required")
    secure, params = tls(values, host, quic=True)
    outbound = {"tls": secure}
    if protocol == "tuic":
        identity, password = (
            uuid(unquote(parts.username or "")),
            text(unquote(parts.password or "")),
        )
        if not password:
            reject("invalid_authentication")
        if boolean(values.get("zero_rtt_handshake", "0")):
            reject("zero_rtt_authentication_disabled_by_policy")
        control, relay = (
            values.get("congestion_control", "cubic"),
            values.get("udp_relay_mode", "native"),
        )
        if control not in {"cubic", "new_reno", "bbr"} or relay not in {
            "native",
            "quic",
        }:
            reject("unsupported_tuic_options")
        if any(
            values.get(field)
            for field in ("obfs", "obfs-password", "obfsPassword", "upmbps", "downmbps")
        ):
            reject("unexpected_tuic_fields")
        outbound.update(
            uuid=identity,
            password=password,
            congestion_control=control,
            udp_relay_mode=relay,
            zero_rtt_handshake=False,
        )
        params.update(congestion_control=control, udp_relay_mode=relay)
        auth = identity + ":" + quote(password, safe="")
    else:
        password = text(
            unquote(parts.username or "")
            + (":" + unquote(parts.password) if parts.password is not None else "")
        )
        if not password:
            reject("invalid_authentication")
        if any(
            values.get(field)
            for field in ("congestion_control", "udp_relay_mode", "zero_rtt_handshake")
        ):
            reject("unexpected_hysteria_fields")
        outbound["password"], auth = password, quote(password, safe="")
        obfs = values.get("obfs", "")
        obfs_password = values.get("obfs-password") or values.get("obfsPassword")
        if obfs:
            if obfs != "salamander" or not obfs_password:
                reject("unsupported_hysteria_obfuscation")
            outbound["obfs"] = {"type": obfs, "password": obfs_password}
            params.update(obfs=obfs, **{"obfs-password": obfs_password})
        elif obfs_password:
            reject("unexpected_hysteria_obfuscation_password")
        for field in ("upmbps", "downmbps"):
            if values.get(field):
                amount = int(values[field])
                if not 1 <= amount <= 100000:
                    reject("invalid_bandwidth_limit")
                outbound["up_mbps" if field == "upmbps" else "down_mbps"] = amount
                params[field] = str(amount)
    return make_spec(
        protocol, host, port, auth, params, outbound, "QUIC / TLS 1.3", "quic"
    )


@dataclass
class ParsedSubscription:
    specs: list[VPNSpec]
    found: int
    rejected: dict[str, int]
    truncated: bool = False


def parse_subscription(data: bytes, *, max_nodes=10000):
    """Plain URI lists and whole-list base64, with bounded decoding and deduplication."""
    try:
        body = data.decode("utf-8-sig").strip()
    except UnicodeError:
        reject("subscription_not_utf8")
    for _ in range(2):
        if "://" in body:
            break
        compact = re.sub(r"\s+", "", body)
        if not compact or not re.fullmatch(r"[A-Za-z0-9_+/=-]+", compact):
            break
        try:
            body = decode64(compact).decode("utf-8-sig").strip()
        except (ConfigRejected, UnicodeError):
            break
    candidates = re.finditer(
        r"(?i)\b(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\s<>\"'`]+", body
    )
    specs, reasons, found, truncated = {}, Counter(), 0, False
    for match in candidates:
        found += 1
        if found > max_nodes * 10:
            truncated = True
            break
        try:
            spec = VPNSpec.from_uri(match.group())
        except ConfigRejected as error:
            reasons[str(error)] += 1
            continue
        if spec.key not in specs and len(specs) >= max_nodes:
            truncated = True
            continue
        specs[spec.key] = spec
    return ParsedSubscription(list(specs.values()), found, dict(reasons), truncated)


class TLSNegotiation(BaseModel):
    model_config = {"extra": "forbid", "frozen": True}
    version: Literal["1.2", "1.3"]
    cipher: str


class LatencyProbe(BaseModel):
    model_config = {"extra": "forbid"}
    url: str = Field(max_length=2048)
    first_response_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    rtt_ms: list[Annotated[float, Field(ge=0, allow_inf_nan=False)]] = Field(
        default_factory=list, max_length=10
    )
    error: str | None = Field(default=None, max_length=300)

    @property
    def latency_ms(self):
        return median(self.rtt_ms[1:] or self.rtt_ms) if self.rtt_ms else None


def probe_provider(url):
    host = (urlsplit(url).hostname or "").lower()
    for suffix, provider in (
        ("gstatic.com", "google.com"),
        ("youtube.com", "google.com"),
        ("google.com", "google.com"),
        ("cloudflare.com", "cloudflare.com"),
    ):
        if host == suffix or host.endswith("." + suffix):
            return provider
    return host


class VPNObservation(BaseModel):
    model_config = {"extra": "forbid"}
    checker_version: int = Field(default=1, ge=1)
    validation_key: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    id: UUID = Field(default_factory=uuid4)
    round_id: UUID | None = None
    # Archived measurements belong to a pre-normalization client configuration.
    original_node_key: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    original_validation_key: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    original_round_id: UUID | None = None
    check_kind: Literal["full", "health"] = "full"
    final: bool = True
    health_validation_key: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    available_ok: bool | None = None
    required_health_probes: int = Field(default=2, ge=1, le=10)
    checker_error: bool = False
    config_error: bool = False
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_reachable_at: datetime | None = None
    samples: int = Field(ge=1, le=10)
    dns_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    duration_ms: float = Field(default=0, ge=0, allow_inf_nan=False)
    resolved_ip: str | None = None
    exit_ip: str | None = None
    country_code: str | None = None
    endpoint_country_code: str | None = None
    geo_source: str | None = None
    tls_sessions: list[TLSNegotiation] = Field(default_factory=list, max_length=128)
    latency_probes: list[LatencyProbe] = Field(default_factory=list, max_length=10)
    first_response_ms: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    rtt_ms: list[float] = Field(default_factory=list, max_length=100)
    download_bytes: int = Field(default=0, ge=0, le=4194304)
    download_ms: float | None = Field(default=None, gt=0, allow_inf_nan=False)
    download_ok: bool = False
    download_first_response_ms: float | None = Field(
        default=None, ge=0, allow_inf_nan=False
    )
    upload_bytes: int = Field(default=0, ge=0, le=4194304)
    upload_confirmed_bytes: int = Field(default=0, ge=0, le=4194304)
    upload_ms: float | None = Field(default=None, gt=0, allow_inf_nan=False)
    upload_ok: bool = False
    error: str | None = Field(default=None, max_length=300)
    stage_errors: dict[str, str] = Field(default_factory=dict, max_length=16)
    safety_error: bool = False
    attempt_count: int = Field(default=1, ge=1, le=4)
    attempt_errors: list[str] = Field(default_factory=list, max_length=4)

    @field_validator("checked_at", "last_reachable_at")
    @classmethod
    def aware_timestamp(cls, value):
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("checked_at must have a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("country_code", "endpoint_country_code")
    @classmethod
    def country(cls, value):
        if value is not None and not re.fullmatch(r"[A-Z]{2}", value):
            raise ValueError("country_code must be an ISO alpha-2 code")
        return value

    @field_validator("resolved_ip", "exit_ip")
    @classmethod
    def ip(cls, value):
        if value is not None:
            parsed = ipaddress.ip_address(value)
            if not parsed.is_global:
                raise ValueError("observed IP must be public")
            return str(parsed)
        return value

    @field_validator("rtt_ms")
    @classmethod
    def timings(cls, value):
        if any(not math.isfinite(item) or item < 0 for item in value):
            raise ValueError("invalid RTT")
        return value

    @property
    def download_mbps(self):
        return (
            self.download_bytes * 8 / (self.download_ms * 1000)
            if self.download_ok and self.download_ms
            else None
        )

    @property
    def upload_mbps(self):
        return (
            self.upload_confirmed_bytes * 8 / (self.upload_ms * 1000)
            if self.upload_ok and self.upload_ms
            else None
        )

    @property
    def latency_ms(self):
        if self.checker_version >= MIN_VALIDATED_CHECKER_VERSION:
            values = [
                probe.latency_ms
                for probe in self.latency_probes
                if probe.latency_ms is not None
            ]
            return median(values) if values else None
        return (
            (self.first_response_ms + median(self.rtt_ms)) / 2
            if self.first_response_ms is not None and self.rtt_ms
            else None
        )

    @property
    def reachable(self):
        if self.safety_error or self.checker_error or self.config_error:
            return False
        if self.checker_version < MIN_VALIDATED_CHECKER_VERSION:
            return self.working
        return bool(
            self.validation_key
            and self.latency_probes
            and self.rtt_ms
            == [rtt for probe in self.latency_probes for rtt in probe.rtt_ms]
            and any(probe.rtt_ms for probe in self.latency_probes)
        )

    @property
    def available(self):
        if self.check_kind == "health" and self.checker_version < 4:
            return False
        if not self.reachable:
            return False
        if self.checker_version < 4:
            return self.working
        providers = {
            probe_provider(probe.url) for probe in self.latency_probes if probe.rtt_ms
        }
        return bool(
            self.health_validation_key and len(providers) >= self.required_health_probes
        )

    @property
    def quality_round(self):
        return (
            self.check_kind == "full"
            and self.final
            and not self.checker_error
            and not self.config_error
        )

    @property
    def traffic_verified(self):
        return bool(
            not self.safety_error
            and self.exit_ip
            and self.download_ok
            and self.download_bytes > 0
            and self.download_mbps is not None
            and self.upload_ok
            and self.upload_bytes == self.upload_confirmed_bytes > 0
            and self.upload_mbps is not None
        )

    @property
    def complete(self):
        return bool(
            self.working
            and not self.stage_errors
            and self.error is None
            and all(
                len(probe.rtt_ms) == self.samples and probe.error is None
                for probe in self.latency_probes
            )
        )

    @property
    def working(self):
        if self.safety_error or self.checker_error or self.config_error:
            return False
        if self.check_kind == "health":
            return self.available
        if self.checker_version >= 3:
            # A new node still needs verified download, acknowledged upload and
            # exit trace. Missing individual 204 targets is a quality limitation.
            return self.reachable and self.traffic_verified
        complete = bool(
            self.exit_ip
            and self.download_ok
            and self.download_bytes > 0
            and self.download_mbps is not None
            and self.error is None
        )
        if self.checker_version < MIN_VALIDATED_CHECKER_VERSION:
            return complete and len(self.rtt_ms) == self.samples
        probes_ok = bool(
            self.latency_probes
            and len({probe.url for probe in self.latency_probes})
            == len(self.latency_probes)
            and all(
                len(probe.rtt_ms) == self.samples
                and probe.first_response_ms is not None
                and probe.error is None
                for probe in self.latency_probes
            )
            and self.rtt_ms
            == [rtt for probe in self.latency_probes for rtt in probe.rtt_ms]
        )
        return bool(
            complete
            and self.validation_key
            and probes_ok
            and self.upload_ok
            and self.upload_bytes == self.upload_confirmed_bytes > 0
            and self.upload_mbps is not None
        )


def rating(
    observations: list[VPNObservation], *, fallback: VPNObservation | None = None
):
    rounds = {}
    for item in sorted(observations, key=lambda item: (item.checked_at, str(item.id))):
        if item.quality_round:
            rounds.setdefault(item.round_id or item.id, item)
    recent = list(rounds.values())[-HISTORY_WINDOW:]
    if recent:
        latest = recent[-1]
        recent = [
            item
            for item in recent
            if (
                min(item.checker_version, MIN_VALIDATED_CHECKER_VERSION),
                item.validation_key,
            )
            == (
                min(latest.checker_version, MIN_VALIDATED_CHECKER_VERSION),
                latest.validation_key,
            )
        ]
    total, successes = len(recent), sum(item.working for item in recent)
    if not total:
        return dict(
            stability_score=0.0,
            speed_score=0.0,
            rating=0.0,
            latency_ms=None,
            download_mbps=None,
            upload_mbps=None,
        )
    p, z = successes / total, 1.96
    stability = (
        100
        * (
            p
            + z * z / (2 * total)
            - z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
        )
        / (1 + z * z / total)
    )
    latency_samples = [
        item.latency_ms
        for item in recent
        if item.working and item.latency_ms is not None
    ]
    latency = (
        median(latency_samples)
        if latency_samples
        else (fallback.latency_ms if fallback else None)
    )
    throughput = [item.download_mbps for item in recent if item.working]
    mbps = (
        median(throughput)
        if throughput
        else (fallback.download_mbps if fallback else None)
    )
    upload_samples = [
        item.upload_mbps
        for item in recent
        if item.working and item.upload_mbps is not None
    ]
    upload = (
        median(upload_samples)
        if upload_samples
        else (fallback.upload_mbps if fallback else None)
    )
    bandwidth_mbps = (
        min(mbps, upload) if mbps is not None and upload is not None else mbps
    )
    responsiveness = 100 / (1 + latency / 250) if latency is not None else 0.0
    bandwidth = (
        100 * bandwidth_mbps / (bandwidth_mbps + 10)
        if bandwidth_mbps is not None
        else 0.0
    )
    speed = (responsiveness + bandwidth) / 2
    reachable = sum(item.reachable for item in recent)
    availability_p = reachable / total
    confidence = (
        100
        * (
            availability_p
            + z * z / (2 * total)
            - z
            * math.sqrt(
                availability_p * (1 - availability_p) / total
                + z * z / (4 * total * total)
            )
        )
        / (1 + z * z / total)
    )

    def quality(item):
        if item.safety_error:
            return 0.0
        coverage = sum(len(probe.rtt_ms) for probe in item.latency_probes) / max(
            1, len(item.latency_probes) * item.samples
        )
        weight = (
            1.0
            if item.complete
            else (
                0.7 * coverage
                if item.working
                else 0.3 * coverage
                if item.reachable
                else 0.0
            )
        )
        return weight / (1 + 0.15 * (item.attempt_count - 1))

    quality_score = sum(quality(item) for item in recent) / total
    score = max(0.0, confidence) * (0.5 + 0.5 * speed / 100) * quality_score
    if not recent[-1].reachable:
        score *= 0.2
    if fallback is not None and not recent[-1].safety_error:
        # A reserved, previously verified node has a low nonzero score even
        # after its successful samples have fallen out of the bounded window.
        score = max(score, 0.25)
    if recent[-1].safety_error:
        score = 0.0
    return dict(
        stability_score=round(max(0.0, stability), 4),
        speed_score=round(speed, 4),
        rating=round(score, 4),
        latency_ms=latency,
        download_mbps=mbps,
        upload_mbps=upload,
    )
