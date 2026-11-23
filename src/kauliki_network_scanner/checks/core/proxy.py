"""HTTP/SOCKS proxy URLs with credentials hidden in configuration diagnostics."""

from typing import Annotated
from urllib.parse import urlsplit

from pydantic import AfterValidator, Field, SecretStr


def proxy_url(value: SecretStr):
    try:
        raw = value.get_secret_value()
        parts = urlsplit(raw)
        if (
            parts.scheme not in {"http", "socks4", "socks5", "socks5h"}
            or not parts.hostname
            or parts.port is None
            or not 1 <= parts.port <= 65535
            or parts.path not in {"", "/"}
            or parts.query
            or parts.fragment
            or any(char.isspace() or ord(char) < 32 for char in raw)
            or (parts.username is None) != (parts.password is None)
        ):
            raise ValueError
    except ValueError:
        raise ValueError(
            "proxy requires an HTTP/SOCKS URL with a host and port; "
            "credentials must include both username and password"
        ) from None
    return value


ProxyURL = Annotated[SecretStr, Field(max_length=2048), AfterValidator(proxy_url)]
