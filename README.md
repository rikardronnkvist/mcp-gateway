# mcp-gateway

MCP Gateway to allow private MCPs via Authentik.

A small [FastMCP](https://gofastmcp.com) proxy that puts OAuth (OIDC) in front of
**one** internal MCP server. Build the image once, run one instance per backend:

```
claude.ai ──OAuth──▶ Traefik ──▶ mcp-gateway ──(bearer, internal net)──▶ backend MCP
```

- Clients authenticate through your IdP (built for Authentik) via FastMCP's `OIDCProxy`,
  including Dynamic Client Registration for claude.ai / Claude Desktop.
- Upstream access tokens are verified against the IdP's JWKS with **issuer and audience
  (= client_id)** checks, so a token for another app on the same IdP is rejected.
- The client's token is **never** forwarded to the backend; the gateway uses its own
  `BACKEND_TOKEN` instead.
- Optional tool allowlist/denylist and subject allowlist.

## Configuration

| Variable | Required | Description |
|---|---|---|
| `BACKEND_URL` | yes | Internal MCP endpoint, e.g. `http://my-mcp:8000/mcp` |
| `BACKEND_TOKEN` | no | Sent as `Authorization: Bearer …` to the backend |
| `BASE_URL` | yes | Public URL of this gateway, e.g. `https://my-mcp.example.com` |
| `OIDC_CONFIG_URL` | yes | IdP discovery URL (`…/.well-known/openid-configuration`) |
| `OIDC_CLIENT_ID` | yes | |
| `OIDC_CLIENT_SECRET` | yes | |
| `JWT_SIGNING_KEY` | yes | Random, unique per instance (`openssl rand -base64 48`). Signs the tokens the gateway issues and encrypts its client store. |
| `OIDC_SCOPES` | no | Default `openid profile email` |
| `OIDC_ALGORITHM` | no | Default `RS256` |
| `ALLOW_TOOLS` | no | Comma-separated allowlist. **Preferred** – new backend tools stay hidden. |
| `HIDE_TOOLS` | no | Comma-separated denylist. Mutually exclusive with `ALLOW_TOOLS`. |
| `ALLOWED_SUBJECTS` | no | Comma-separated `sub` / `email` / `preferred_username` values. Defense in depth on top of IdP policy. |
| `GATEWAY_NAME` | no | Server name shown to clients |
| `PORT` / `HOST` / `LOG_LEVEL` | no | Defaults `8000` / `0.0.0.0` / `INFO` |

`/data` holds the encrypted OAuth client registrations. Mount it on persistent storage
so clients don't have to re-register after a restart. The container runs as uid `10001`.

`GET /health` is an unauthenticated liveness probe; it does not contact the backend.

## Authentik setup

1. **Provider** → OAuth2/OpenID Provider, client type *Confidential*.
   - Redirect URI (strict): `https://<gateway-host>/auth/callback`
   - **Signing key: set one** (RS256). Without it access tokens are HS256 and JWKS verification fails.
   - Scopes: `openid`, `profile`, `email`.
2. **Application** bound to the provider. Use the slug in `OIDC_CONFIG_URL`:
   `https://<authentik>/application/o/<slug>/.well-known/openid-configuration`
3. **Policy binding** on the application limiting it to your user/group. Consider requiring
   MFA for gateways in front of anything that can change state.

## Docker Swarm example

Keep the backend on an internal network shared only with its gateway:

```yaml
services:
  my-mcp:
    image: example/my-mcp:1.2.3
    environment:
      AUTH_TOKEN: ${MY_MCP_TOKEN}
    networks: [mcp]            # no traefik network, no ports, no labels

  my-mcp-gw:
    image: ghcr.io/rikardronnkvist/mcp-gateway:0.1.0
    environment:
      GATEWAY_NAME: My MCP
      BACKEND_URL: http://my-mcp:8000/mcp
      BACKEND_TOKEN: ${MY_MCP_TOKEN}
      BASE_URL: https://my-mcp.example.com
      OIDC_CONFIG_URL: https://auth.example.com/application/o/my-mcp/.well-known/openid-configuration
      OIDC_CLIENT_ID: ${MY_MCP_OIDC_CLIENT_ID}
      OIDC_CLIENT_SECRET: ${MY_MCP_OIDC_CLIENT_SECRET}
      JWT_SIGNING_KEY: ${MY_MCP_JWT_SIGNING_KEY}
      ALLOW_TOOLS: get_status,get_report
    volumes:
      - /srv/mcp-gateway/my-mcp:/data
    networks: [traefik, mcp]
    deploy:
      labels:
        - traefik.enable=true
        - traefik.docker.network=traefik
        - traefik.http.routers.my-mcp.rule=Host(`my-mcp.example.com`)
        - traefik.http.routers.my-mcp.entrypoints=websecure
        - traefik.http.routers.my-mcp.tls.certresolver=le
        - traefik.http.services.my-mcp.loadbalancer.server.port=8000

networks:
  traefik:
    external: true
  mcp:
    driver: overlay
    internal: true
    driver_opts:
      encrypted: "true"
```

Then add `https://my-mcp.example.com/mcp` as a custom connector in Claude.

## Development

```sh
pip install -r requirements-dev.txt
pytest
```

Tests spin up a real backend MCP server and a fake OIDC provider locally; no network needed.

## Releases

Push a tag `vX.Y.Z` → image `ghcr.io/rikardronnkvist/mcp-gateway:X.Y.Z` (and `X.Y`).
Pushes to `main` publish `:edge`. There is no `latest` tag – pin a version.
