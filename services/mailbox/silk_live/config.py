"""Explicit approved deployment configuration; never creates credentials or grants."""
from dataclasses import dataclass
from urllib.parse import urlsplit
from pydantic import AnyHttpUrl


@dataclass(frozen=True)
class Settings:
    issuer_url: str
    resource_url: str
    jwks_url: str
    allowed_client_ids: tuple[str, ...]
    allowed_origins: tuple[str, ...] = ()

    def __post_init__(self):
        for label, value in (("issuer", self.issuer_url), ("resource", self.resource_url), ("JWKS", self.jwks_url)):
            parsed = urlsplit(value)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or len(value) > 2048:
                raise ValueError(f"{label} must be a canonical HTTPS URL without credentials, query, or fragment")
        if str(AnyHttpUrl(self.issuer_url)) != self.issuer_url or str(AnyHttpUrl(self.resource_url)) != self.resource_url:
            raise ValueError("Issuer and resource must use exact canonical URL forms, including an issuer root trailing slash")
        if urlsplit(self.resource_url).path != "/mcp":
            raise ValueError("The configured resource must use the reviewed /mcp endpoint")
        if not self.allowed_client_ids or len(self.allowed_client_ids) > 8 or any(type(x) is not str or not 1 <= len(x) <= 200 for x in self.allowed_client_ids):
            raise ValueError("Explicitly allow one to eight reviewed OAuth client IDs")
        for origin in self.allowed_origins:
            parsed = urlsplit(origin)
            if parsed.scheme != "https" or not parsed.netloc or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password or "*" in origin:
                raise ValueError("Allowed origins must be exact HTTPS origins without wildcards")

    @property
    def host(self):
        return urlsplit(self.resource_url).netloc

    @property
    def origins(self):
        parsed = urlsplit(self.resource_url)
        return tuple(dict.fromkeys((f"https://{parsed.netloc}", *self.allowed_origins)))
