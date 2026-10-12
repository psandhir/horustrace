"""Local SIWC authorization contract tests. All network calls are mocked."""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from urllib import parse, request

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from horustrace import siwc_auth as a


def test_authorize_parameters_and_pkce_loopback(tmp_path: Path, monkeypatch):
    seen = {}

    def browser(url):
        query = parse.parse_qs(parse.urlsplit(url).query)
        seen.update({key: value[0] for key, value in query.items()})
        assert seen["client_id"] == "dynamic_agent_client"
        assert seen["agent_name_hint"] == "HorusScan"
        assert seen["redirect_uri"].startswith("http://127.0.0.1:")
        assert seen["redirect_uri"].endswith("/auth/callback")
        assert seen["code_challenge_method"] == "S256"
        assert {"openid", "resource.invoke", "chatgpt.tokens.use.direct"}.issubset(
            set(seen["scope"].split())
        )

        def callback():
            url = (seen["redirect_uri"] + "?" + parse.urlencode({
                "code": "code-fixture",
                "state": seen["state"],
                "client_id": "oaiapp_fixture",
            }))
            with request.urlopen(url, timeout=3) as response:
                assert response.status == 200

        threading.Thread(target=callback, daemon=True).start()
        return True

    def exchange(endpoint, data):
        assert endpoint == a.TOKEN_URL
        assert data["client_id"] == "oaiapp_fixture"
        assert data["redirect_uri"] == seen["redirect_uri"]
        import base64
        import hashlib
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(data["code_verifier"].encode()).digest()
        ).rstrip(b"=").decode()
        assert expected == seen["code_challenge"]
        return {
            "id_token": "signed-id-fixture",
            "access_token": "access-fixture",
            "refresh_token": "refresh-fixture",
            "token_type": "Bearer",
            "scope": a.SCOPES,
            "expires_in": 3600,
        }

    monkeypatch.setattr(a, "_post_form", exchange)
    monkeypatch.setattr(
        a, "verify_id_token",
        lambda token, client, nonce: {
            "sub": "subject-fixture", "email": "person@example.com"
        },
    )
    result = a.login(root=tmp_path, open_browser=browser, timeout_seconds=5)
    assert result["plan_enabled"]
    assert result["client_id"] == "oaiapp_fixture"
    assert len(result["id"]) == 32
    assert a.accounts(tmp_path)[0]["signed_in"]
    assert a.get_access_token(root=tmp_path) == "access-fixture"
    assert "access-fixture" not in json.dumps(a.accounts(tmp_path))
    if os.name == "posix":
        assert (tmp_path / ("account-" + result["id"] + ".json")).stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("query,previous,match", [
    ("code=x&state=wrong&client_id=oaiapp_a", None, "state mismatch"),
    ("code=x&state=right&client_id=dynamic_agent_client", None, "issued client"),
    ("code=x&state=right", None, "issued client"),
    ("code=x&state=right&client_id=oaiapp_other", "oaiapp_a", "client ID changed"),
    ("code=x&state=right&state=right&client_id=oaiapp_a", None, "duplicate"),
    ("error=access_denied&state=right", None, "declined"),
])
def test_callback_failure(query, previous, match):
    with pytest.raises(a.ChatGPTAuthError, match=match):
        a._callback_values(query, "right", previous)


def test_plan_scope_is_required():
    with pytest.raises(a.ChatGPTAuthError, match="permission"):
        a._record({
            "access_token": "a", "refresh_token": "r", "id_token": "i",
            "scope": "openid profile email", "token_type": "Bearer", "expires_in": 3600,
        }, "oaiapp_a", {"sub": "subject"}, "urn:uuid:x")


def test_account_separation_and_reauth_rejects_identity_swap(tmp_path, monkeypatch):
    a._write(a._profile_path("a" * 32, tmp_path), {
        "client_id": "oaiapp_a", "subject": "alice", "scopes": sorted(a.REQUIRED_SCOPES),
        "access_token": "alice-token", "refresh_token": "alice-refresh",
        "id_token": "alice-id", "expires_at": time.time() + 300,
    })
    a._write(a._profile_path("b" * 32, tmp_path), {
        "client_id": "oaiapp_b", "subject": "bob", "scopes": sorted(a.REQUIRED_SCOPES),
        "access_token": "bob-token", "refresh_token": "bob-refresh",
        "id_token": "bob-id", "expires_at": time.time() + 300,
    })
    with pytest.raises(a.ChatGPTAuthError, match="multiple"):
        a.get_access_token(root=tmp_path)
    assert a.get_access_token("a" * 32, tmp_path) == "alice-token"
    assert a.get_access_token("b" * 32, tmp_path) == "bob-token"
    with pytest.raises(a.ChatGPTAuthError, match="unknown"):
        a.get_access_token("c" * 32, tmp_path)


def test_refresh_rotates_and_persists(tmp_path, monkeypatch):
    key = "a" * 32
    a._write(a._profile_path(key, tmp_path), {
        "client_id": "oaiapp_a", "subject": "alice", "scopes": sorted(a.REQUIRED_SCOPES),
        "access_token": "expired", "refresh_token": "refresh-old",
        "id_token": "validated-id", "expires_at": time.time() - 1,
    })

    def exchange(endpoint, data):
        assert data["grant_type"] == "refresh_token"
        assert data["refresh_token"] == "refresh-old"
        return {"access_token": "new-access", "refresh_token": "refresh-new",
                "scope": "resource.invoke chatgpt.tokens.use.direct",
                "expires_in": 3600}

    monkeypatch.setattr(a, "_post_form", exchange)
    assert a.get_access_token(root=tmp_path) == "new-access"
    record = a._read(a._profile_path(key, tmp_path))
    assert record["refresh_token"] == "refresh-new"
    assert record["id_token"] == "validated-id"


def test_symlink_storage_is_rejected(tmp_path):
    other = tmp_path / "real"
    other.mkdir()
    link = tmp_path / "link"
    link.symlink_to(other, target_is_directory=True)
    with pytest.raises(a.ChatGPTAuthError, match="symlink"):
        a._folder(link)


def test_real_jws_crypto_verification_checks_audience_nonce_signature(monkeypatch):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()
    now = int(time.time())
    payload = {
        "iss": a.ISSUER, "aud": "oaiapp_test", "sub": "subject-fixture",
        "nonce": "nonce-ok", "iat": now, "exp": now + 3600,
    }
    signed = jwt.encode(payload, private, algorithm="RS256", headers={"kid": "k1"})

    class Key:
        key = public

    monkeypatch.setattr(jwt.PyJWKClient, "get_signing_key_from_jwt", lambda self, token: Key())
    assert a.verify_id_token(signed, "oaiapp_test", "nonce-ok")["sub"] == "subject-fixture"
    with pytest.raises(a.ChatGPTAuthError, match="nonce"):
        a.verify_id_token(signed, "oaiapp_test", "incorrect")
    with pytest.raises(a.ChatGPTAuthError, match="validation"):
        a.verify_id_token(signed, "wrong-audience", "nonce-ok")
