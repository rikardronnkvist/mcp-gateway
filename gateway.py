"""MCP gateway: OAuth (OIDC) in front of a single internal MCP server.

One image, one backend per running instance. All configuration comes from
environment variables, see README.md.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from fastmcp import FastMCP
from fastmcp.client.transports import StreamableHttpTransport
from fastmcp.exceptions import AuthorizationError
from fastmcp.server import create_proxy
from fastmcp.server.auth import AuthProvider
from fastmcp.server.auth.oidc_proxy import OIDCConfiguration, OIDCProxy
from fastmcp.server.auth.providers.jwt import JWTVerifier
from fastmcp.server.dependencies import get_access_token
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.providers.proxy import ProxyClient
from mcp.types import Icon
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

log = logging.getLogger("mcp-gateway")

DEFAULT_SCOPES = "openid profile email"
# Requested from the IdP only. Without offline_access Authentik issues no
# refresh token, so clients must re-authenticate when the (short-lived)
# upstream access token expires.
DEFAULT_UPSTREAM_EXTRA_SCOPES = "offline_access"

ICON_MAX_BYTES = 1024 * 1024
ICON_TYPES = {
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
}


class ConfigError(Exception):
    pass


def env(name: str, default: str | None = None, *, required: bool = False) -> str | None:
    value = os.environ.get(name, "").strip() or default
    if required and not value:
        raise ConfigError(f"Missing required environment variable: {name}")
    return value


def env_list(name: str) -> list[str]:
    raw = env(name) or ""
    return [item.strip() for item in raw.replace(" ", ",").split(",") if item.strip()]


def load_icon() -> tuple[bytes, str] | None:
    """Optional server icon from GATEWAY_ICON (a file path inside the container).

    Returns (data, mime_type), or None when no icon is configured.
    """
    path = env("GATEWAY_ICON")
    if not path:
        return None
    p = Path(path)
    mime = ICON_TYPES.get(p.suffix.lower())
    if mime is None:
        raise ConfigError(
            f"GATEWAY_ICON must be one of {', '.join(sorted(ICON_TYPES))}: {path}"
        )
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise ConfigError(f"Cannot read GATEWAY_ICON {path}: {exc}") from exc
    if not data or len(data) > ICON_MAX_BYTES:
        raise ConfigError(f"GATEWAY_ICON must be 1 byte to {ICON_MAX_BYTES} bytes: {path}")
    return data, mime


def build_auth() -> AuthProvider:
    """OIDC proxy against the upstream IdP (e.g. Authentik).

    Upstream access tokens are verified against the IdP's JWKS with issuer and
    audience (= client_id) checks, so a token issued to another application
    on the same IdP is rejected.
    """
    config_url = env("OIDC_CONFIG_URL", required=True)
    client_id = env("OIDC_CLIENT_ID", required=True)
    base_url = env("BASE_URL", required=True)
    scopes = (env("OIDC_SCOPES") or DEFAULT_SCOPES).split()

    # Cached by FastMCP, so OIDCProxy below reuses this fetch.
    oidc = OIDCConfiguration.get_oidc_configuration(
        AnyHttpUrl(config_url), strict=None, timeout_seconds=10
    )
    if not oidc.jwks_uri or not oidc.issuer:
        raise ConfigError(f"OIDC discovery at {config_url} lacks jwks_uri/issuer")

    verifier = JWTVerifier(
        jwks_uri=str(oidc.jwks_uri),
        issuer=str(oidc.issuer),
        audience=client_id,
        algorithm=env("OIDC_ALGORITHM", "RS256"),
        base_url=base_url,
    )

    # Explicitly set (even empty) overrides the default; empty disables it.
    extra = os.environ.get("OIDC_UPSTREAM_EXTRA_SCOPES", DEFAULT_UPSTREAM_EXTRA_SCOPES).split()

    return GatewayOIDCProxy(
        upstream_extra_scopes=extra,
        config_url=config_url,
        client_id=client_id,
        client_secret=env("OIDC_CLIENT_SECRET", required=True),
        base_url=base_url,
        jwt_signing_key=env("JWT_SIGNING_KEY", required=True),
        token_verifier=verifier,
        valid_scopes=scopes,
        # Keep token audience deterministic (client_id); don't send RFC 8707
        # resource indicators upstream.
        forward_resource=False,
    )


class GatewayOIDCProxy(OIDCProxy):
    """OIDCProxy that always requests extra scopes (e.g. offline_access) upstream.

    The extra scopes are added only to the IdP authorize request, not to the
    scopes advertised to or granted to MCP clients.
    """

    def __init__(self, *, upstream_extra_scopes: list[str] | None = None, **kwargs):
        super().__init__(**kwargs)
        self._upstream_extra_scopes = list(upstream_extra_scopes or [])

    def _build_upstream_authorize_url(self, txn_id, transaction):
        if self._upstream_extra_scopes:
            scopes = list(transaction.get("scopes") or self.required_scopes or [])
            scopes += [s for s in self._upstream_extra_scopes if s not in scopes]
            transaction = {**transaction, "scopes": scopes}
        return super()._build_upstream_authorize_url(txn_id, transaction)


class AllowedSubjectsMiddleware(Middleware):
    """Defense in depth on top of the IdP's access policy.

    Rejects any request whose upstream token doesn't carry one of the
    allowed values in sub, email or preferred_username.
    """

    CLAIMS = ("sub", "email", "preferred_username")

    def __init__(self, allowed: list[str]) -> None:
        self.allowed = {a.lower() for a in allowed}

    def is_allowed(self, claims: dict | None) -> bool:
        claims = claims or {}
        values = {str(claims[c]).lower() for c in self.CLAIMS if claims.get(c)}
        return bool(values & self.allowed)

    async def on_request(self, context: MiddlewareContext, call_next):
        token = get_access_token()
        if token is None or not self.is_allowed(token.claims):
            log.warning("Rejected request from subject not in ALLOWED_SUBJECTS")
            raise AuthorizationError("Not allowed")
        return await call_next(context)


def build_gateway(auth: AuthProvider | None) -> FastMCP:
    backend_url = env("BACKEND_URL", required=True)
    headers: dict[str, str] = {}
    if token := env("BACKEND_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"

    backend = ProxyClient(
        StreamableHttpTransport(backend_url, headers=headers),
        # Never pass the client's gateway token on to the backend
        forward_incoming_headers=False,
    )

    icon = load_icon()
    icons = None
    if icon:
        base_url = env("BASE_URL")
        if not base_url:
            raise ConfigError("BASE_URL is required when GATEWAY_ICON is set")
        icons = [Icon(src=f"{base_url.rstrip('/')}/icon", mime_type=icon[1])]

    gateway = FastMCP(env("GATEWAY_NAME", "MCP Gateway"), auth=auth, icons=icons)
    gateway.mount(create_proxy(backend))

    allow_tools = set(env_list("ALLOW_TOOLS"))
    hide_tools = set(env_list("HIDE_TOOLS"))
    if allow_tools and hide_tools:
        raise ConfigError("Set either ALLOW_TOOLS or HIDE_TOOLS, not both")
    if allow_tools:
        gateway.enable(names=allow_tools, only=True)
        log.info("Tool allowlist: %s", ", ".join(sorted(allow_tools)))
    elif hide_tools:
        gateway.disable(names=hide_tools)
        log.info("Hidden tools: %s", ", ".join(sorted(hide_tools)))
    else:
        log.warning("No ALLOW_TOOLS/HIDE_TOOLS set: all backend tools are exposed")

    if allowed := env_list("ALLOWED_SUBJECTS"):
        gateway.add_middleware(AllowedSubjectsMiddleware(allowed))
        log.info("Subject allowlist enabled (%d entries)", len(allowed))
    else:
        log.warning("ALLOWED_SUBJECTS not set: relying on IdP policy only")

    @gateway.custom_route("/health", methods=["GET"], include_in_schema=False)
    async def health(_: Request) -> JSONResponse:
        # Liveness only; does not contact the backend.
        return JSONResponse({"status": "ok"})

    if icon:
        icon_data, icon_mime = icon

        # Unauthenticated, like /health: clients fetch it before OAuth.
        async def serve_icon(_: Request) -> Response:
            return Response(
                icon_data,
                media_type=icon_mime,
                headers={
                    "Cache-Control": "public, max-age=86400",
                    "X-Content-Type-Options": "nosniff",
                    # SVG can carry script; never let it run on the OAuth origin.
                    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
                },
            )

        for route in ("/icon", "/favicon.ico"):
            gateway.custom_route(route, methods=["GET"], include_in_schema=False)(serve_icon)
        log.info("Serving icon (%s, %d bytes)", icon_mime, len(icon_data))

    return gateway


def main() -> None:
    logging.basicConfig(
        level=env("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        gateway = build_gateway(build_auth())
    except ConfigError as exc:
        log.error("%s", exc)
        sys.exit(2)

    gateway.run(
        transport="http",
        host=env("HOST", "0.0.0.0"),
        port=int(env("PORT", "8000")),
    )


if __name__ == "__main__":
    main()
