"""Integration tests: real backend over HTTP, fake OIDC provider, no network."""

from __future__ import annotations

import base64
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import uvicorn
from cryptography.hazmat.primitives import serialization
from fastmcp import Client, FastMCP
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from fastmcp.server.dependencies import get_http_headers
from starlette.testclient import TestClient

import gateway

BACKEND_TOKEN = "backend-test-token"
CLIENT_ID = "test-client"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def serve_in_thread(app, port: int) -> None:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(100):
        if server.started:
            return
        time.sleep(0.05)
    raise RuntimeError("server did not start")


@pytest.fixture(scope="session")
def backend_url() -> str:
    backend = FastMCP("backend")

    @backend.tool
    def get_status() -> str:
        return "ok"

    @backend.tool
    def get_report() -> str:
        return "report"

    @backend.tool
    def run_sql(query: str) -> str:
        return "should be hidden"

    @backend.tool
    def echo_auth() -> str:
        return get_http_headers(include={"authorization"}).get("authorization", "")

    port = free_port()
    serve_in_thread(backend.http_app(), port)
    return f"http://127.0.0.1:{port}/mcp"


@pytest.fixture
def base_env(monkeypatch, backend_url):
    for var in ("ALLOW_TOOLS", "HIDE_TOOLS", "ALLOWED_SUBJECTS"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("BACKEND_URL", backend_url)
    monkeypatch.setenv("BACKEND_TOKEN", BACKEND_TOKEN)


async def tool_names(server: FastMCP) -> set[str]:
    async with Client(server) as client:
        return {t.name for t in await client.list_tools()}


async def test_proxies_all_tools_and_sends_backend_token(base_env):
    gw = gateway.build_gateway(auth=None)
    assert await tool_names(gw) == {"get_status", "get_report", "run_sql", "echo_auth"}
    async with Client(gw) as client:
        result = await client.call_tool("echo_auth")
    assert result.data == f"Bearer {BACKEND_TOKEN}"


async def test_allow_tools(base_env, monkeypatch):
    monkeypatch.setenv("ALLOW_TOOLS", "get_status, get_report")
    gw = gateway.build_gateway(auth=None)
    assert await tool_names(gw) == {"get_status", "get_report"}
    async with Client(gw) as client:
        with pytest.raises(Exception, match="(?i)unknown tool|not found|disabled"):
            await client.call_tool("run_sql", {"query": "select 1"})


async def test_hide_tools(base_env, monkeypatch):
    monkeypatch.setenv("HIDE_TOOLS", "run_sql")
    gw = gateway.build_gateway(auth=None)
    assert "run_sql" not in await tool_names(gw)
    async with Client(gw) as client:
        with pytest.raises(Exception, match="(?i)unknown tool|not found|disabled"):
            await client.call_tool("run_sql", {"query": "select 1"})


def test_allow_and_hide_is_config_error(base_env, monkeypatch):
    monkeypatch.setenv("ALLOW_TOOLS", "a")
    monkeypatch.setenv("HIDE_TOOLS", "b")
    with pytest.raises(gateway.ConfigError):
        gateway.build_gateway(auth=None)


def test_missing_backend_url(monkeypatch):
    monkeypatch.delenv("BACKEND_URL", raising=False)
    with pytest.raises(gateway.ConfigError):
        gateway.build_gateway(auth=None)


def test_subject_matching():
    mw = gateway.AllowedSubjectsMiddleware(["Rikard", "x@example.com"])
    assert mw.is_allowed({"preferred_username": "rikard"})
    assert mw.is_allowed({"email": "X@example.com"})
    assert not mw.is_allowed({"preferred_username": "someone"})
    assert not mw.is_allowed({})
    assert not mw.is_allowed(None)


class _FakeToken:
    def __init__(self, claims):
        self.claims = claims


async def test_subject_middleware_allows_listed_subject(base_env, monkeypatch):
    monkeypatch.setenv("ALLOWED_SUBJECTS", "rikard")
    monkeypatch.setattr(gateway, "get_access_token",
                        lambda: _FakeToken({"preferred_username": "rikard"}))
    gw = gateway.build_gateway(auth=None)
    async with Client(gw) as client:
        assert (await client.call_tool("get_status")).data == "ok"


@pytest.mark.parametrize("token", [None, _FakeToken({"preferred_username": "mallory"})])
async def test_subject_middleware_rejects_others(base_env, monkeypatch, caplog, token):
    monkeypatch.setenv("ALLOWED_SUBJECTS", "rikard")
    monkeypatch.setattr(gateway, "get_access_token", lambda: token)
    gw = gateway.build_gateway(auth=None)
    with pytest.raises(Exception):
        async with Client(gw) as client:
            await client.call_tool("get_status")
    assert "Rejected request" in caplog.text


# --- OIDC ------------------------------------------------------------------


@pytest.fixture(scope="session")
def keypair() -> RSAKeyPair:
    return RSAKeyPair.generate()


@pytest.fixture(scope="session")
def fake_idp(keypair):
    """Minimal OIDC discovery + JWKS server."""
    port = free_port()
    issuer = f"http://127.0.0.1:{port}/application/o/test/"

    pub = serialization.load_pem_public_key(keypair.public_key.encode())
    nums = pub.public_numbers()

    def b64(n: int) -> str:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    docs = {
        "/application/o/test/.well-known/openid-configuration": {
            "issuer": issuer,
            "authorization_endpoint": f"http://127.0.0.1:{port}/authorize",
            "token_endpoint": f"http://127.0.0.1:{port}/token",
            "jwks_uri": f"http://127.0.0.1:{port}/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        },
        "/jwks": {"keys": [{"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
                            "n": b64(nums.n), "e": b64(nums.e)}]},
    }

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = docs.get(self.path)
            self.send_response(200 if body else 404)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body or {}).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return {"issuer": issuer, "config_url": issuer + ".well-known/openid-configuration"}


@pytest.fixture
def oidc_env(base_env, monkeypatch, fake_idp, tmp_path):
    monkeypatch.setenv("OIDC_CONFIG_URL", fake_idp["config_url"])
    monkeypatch.setenv("OIDC_CLIENT_ID", CLIENT_ID)
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "test-secret")
    monkeypatch.setenv("BASE_URL", "https://gw.example.com")
    monkeypatch.setenv("JWT_SIGNING_KEY", "test-signing-key-for-unit-tests-only")
    monkeypatch.setenv("FASTMCP_HOME", str(tmp_path))


def test_http_endpoints_require_auth(oidc_env):
    gw = gateway.build_gateway(gateway.build_auth())
    with TestClient(gw.http_app()) as http:
        assert http.get("/health").json() == {"status": "ok"}
        r = http.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                      headers={"Accept": "application/json, text/event-stream"})
        assert r.status_code == 401
        meta = http.get("/.well-known/oauth-protected-resource/mcp")
        assert meta.status_code == 200
        assert meta.json()["resource"].startswith("https://gw.example.com")


async def test_upstream_token_audience_and_issuer(oidc_env, keypair, fake_idp):
    auth = gateway.build_auth()
    verifier = auth._token_validator
    good = keypair.create_token(subject="u1", issuer=fake_idp["issuer"], audience=CLIENT_ID)
    other_app = keypair.create_token(subject="u1", issuer=fake_idp["issuer"], audience="other-app")
    wrong_iss = keypair.create_token(subject="u1", issuer="https://evil/", audience=CLIENT_ID)
    assert await verifier.verify_token(good) is not None
    assert await verifier.verify_token(other_app) is None
    assert await verifier.verify_token(wrong_iss) is None
