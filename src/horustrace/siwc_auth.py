"""Local, user-consented Sign in with ChatGPT OAuth PKCE for HorusScan.

Only for user-controlled runtimes. Never send these credentials to standard
GitHub-hosted CI, repository secrets, cloud telemetry, or scanner evidence.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import tempfile
import time
import uuid
import webbrowser
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib import error, parse, request

ISSUER = "https://auth.openai.com"
AUTH_URL = ISSUER + "/api/accounts/authorize"
TOKEN_URL = ISSUER + "/api/accounts/oauth/token"
DISCOVERY_URL = ISSUER + "/.well-known/openid-configuration"
JWKS_URL = ISSUER + "/.well-known/jwks.json"
RESOURCE = "https://api.openai.com/v1"
SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
REQUIRED_SCOPES = {"resource.invoke", "chatgpt.tokens.use.direct"}
CALLBACK_PATH = "/auth/callback"
APP_NAME = "HorusScan"
MAX_OAUTH_BYTES = 1024 * 1024


class ChatGPTAuthError(ValueError):
    """Local authorization is missing, expired, denied, or not verified."""


def state_dir() -> Path:
    override = os.environ.get("HORUSTRACE_CHATGPT_CONFIG_DIR")
    return Path(override) if override else Path.home() / ".config" / "horustrace" / "chatgpt"


def _folder(path: Path) -> None:
    if path.is_symlink():
        raise ChatGPTAuthError("credential directory must not be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise ChatGPTAuthError("credential storage must be a directory")
    if os.name == "posix":
        if path.stat().st_uid != os.getuid():
            raise ChatGPTAuthError("credential directory has a different owner")
        path.chmod(0o700)


def _read(path: Path) -> dict:
    if path.is_symlink():
        raise ChatGPTAuthError("credential file must not be a symlink")
    if os.name == "posix":
        st = path.stat()
        if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
            raise ChatGPTAuthError("credential file permissions are not owner-only")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ChatGPTAuthError("invalid credential record")
    return value


def _write(path: Path, value: dict) -> None:
    _folder(path.parent)
    tmp = None
    try:
        fd, name = tempfile.mkstemp(prefix=".siwc-", dir=path.parent)
        tmp = Path(name)
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(value, out, sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        if path.is_symlink():
            raise ChatGPTAuthError("refusing to overwrite a credential symlink")
        os.replace(tmp, path)
        tmp = None
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def host_id(root: Path | None = None) -> str:
    home = root or state_dir()
    _folder(home)
    path = home / "host.json"
    if path.exists():
        value = _read(path).get("ext_agent_host_id")
        if not isinstance(value, str) or not value.startswith("urn:uuid:"):
            raise ChatGPTAuthError("invalid persisted host identifier")
        return value
    value = "urn:uuid:" + str(uuid.uuid4())
    _write(path, {"ext_agent_host_id": value})
    return value


def _profile_key(client_id: str, subject: str) -> str:
    return hashlib.sha256((client_id + "\0" + subject).encode()).hexdigest()[:32]


def _profile_path(account_id: str, root: Path | None = None) -> Path:
    if len(account_id) != 32 or not all(c in "0123456789abcdef" for c in account_id):
        raise ChatGPTAuthError("invalid account identifier")
    return (root or state_dir()) / f"account-{account_id}.json"


def accounts(root: Path | None = None) -> list[dict]:
    home = root or state_dir()
    if not home.exists():
        return []
    _folder(home)
    rows = []
    for path in sorted(home.glob("account-*.json")):
        account_id = path.name[len("account-"):-len(".json")]
        if len(account_id) == 32:
            record = _read(path)
            rows.append({
                "id": account_id,
                "email": record.get("email"),
                "client_id": record.get("client_id"),
                "signed_in": bool(record.get("refresh_token")),
                "plan_enabled": REQUIRED_SCOPES.issubset(record.get("scopes", [])),
            })
    return rows


def _choose(account_id: str | None, root: Path | None = None) -> dict:
    rows = accounts(root)
    if account_id:
        row = next((a for a in rows if a["id"] == account_id), None)
        if row is None:
            raise ChatGPTAuthError("unknown ChatGPT account ID; run chatgpt accounts")
    elif len(rows) == 1:
        row = rows[0]
    elif not rows:
        raise ChatGPTAuthError("no ChatGPT account; run 'horustrace chatgpt login'")
    else:
        raise ChatGPTAuthError("multiple ChatGPT accounts; select --account ID")
    record = _read(_profile_path(row["id"], root))
    record["_local_id"] = row["id"]
    return record


@contextmanager
def _refresh_lock(root: Path):
    """Serialize rotating refresh tokens across processes on Unix."""
    _folder(root)
    if os.name != "posix":
        raise ChatGPTAuthError("automatic plan-token refresh requires a POSIX local runtime")
    import fcntl

    path = root / ".refresh.lock"
    fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if stat.S_IMODE(os.fstat(fd).st_mode) & 0o077:
            raise ChatGPTAuthError("refresh lock must be owner-only")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _post_form(url: str, values: dict[str, str]) -> dict:
    req = request.Request(
        url, data=parse.urlencode(values).encode("utf-8"), method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with request.urlopen(req, timeout=30) as response:
            data = response.read(MAX_OAUTH_BYTES + 1)
    except error.HTTPError as exc:
        raise ChatGPTAuthError(f"ChatGPT authorization endpoint returned HTTP {exc.code}") from exc
    except (error.URLError, TimeoutError) as exc:
        raise ChatGPTAuthError("ChatGPT authorization network request failed") from exc
    if len(data) > MAX_OAUTH_BYTES:
        raise ChatGPTAuthError("ChatGPT authorization response too large")
    try:
        result = json.loads(data)
    except ValueError as exc:
        raise ChatGPTAuthError("invalid authorization response") from exc
    if not isinstance(result, dict):
        raise ChatGPTAuthError("invalid authorization response")
    return result


def verify_id_token(token: str, client_id: str, nonce: str) -> dict:
    """Verify the RS256 JWS signature and issuer, audience, clock and nonce."""
    try:
        import jwt
    except ImportError as exc:
        raise ChatGPTAuthError(
            "install cryptographic validation: pip install 'horustrace[chatgpt]'"
        ) from exc
    try:
        jwks = jwt.PyJWKClient(JWKS_URL)
        key = jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key, algorithms=["RS256"], issuer=ISSUER, audience=client_id,
            options={"require": ["exp", "iat", "sub", "iss", "aud", "nonce"]},
            leeway=5,
        )
    except jwt.PyJWTError as exc:
        raise ChatGPTAuthError("ChatGPT identity token validation failed") from exc
    if (not isinstance(claims.get("sub"), str) or not claims["sub"]
            or not hmac.compare_digest(str(claims.get("nonce", "")), nonce)):
        raise ChatGPTAuthError("ChatGPT identity nonce or subject mismatch")
    return claims


def _record(tokens: dict, client_id: str, claims: dict, stable_host: str) -> dict:
    scope = tokens.get("scope", "")
    granted = set(scope.split()) if isinstance(scope, str) else set()
    if not REQUIRED_SCOPES.issubset(granted):
        raise ChatGPTAuthError("ChatGPT plan usage permission was not granted")
    if str(tokens.get("token_type", "")).lower() != "bearer":
        raise ChatGPTAuthError("authorization did not return a bearer token")
    for field in ("id_token", "access_token", "refresh_token"):
        if not isinstance(tokens.get(field), str) or not tokens[field]:
            raise ChatGPTAuthError(f"authorization missing {field}")
    lifetime = tokens.get("expires_in")
    if not isinstance(lifetime, (int, float)) or lifetime <= 0:
        raise ChatGPTAuthError("authorization returned invalid token lifetime")
    return {
        "issuer": ISSUER,
        "subject": claims["sub"],
        "email": claims.get("email"),
        "client_id": client_id,
        "ext_agent_host_id": stable_host,
        "id_token": tokens["id_token"],
        "access_token": tokens["access_token"],
        "refresh_token": tokens["refresh_token"],
        "token_type": "Bearer",
        "scopes": sorted(granted),
        "expires_at": time.time() + float(lifetime),
        "earliest_refresh_at": tokens.get("earliest_refresh_at"),
    }


def _callback_values(query: str, state: str, prior_client: str | None) -> tuple[str, str]:
    params = parse.parse_qs(query, keep_blank_values=True)
    if any(len(v) != 1 for v in params.values()):
        raise ChatGPTAuthError("duplicate OAuth callback parameters")
    actual = params.get("state", [""])[0]
    if not hmac.compare_digest(actual, state):
        raise ChatGPTAuthError("OAuth callback state mismatch")
    if params.get("error"):
        raise ChatGPTAuthError("ChatGPT sign-in declined or denied")
    code = params.get("code", [""])[0]
    issued = params.get("client_id", [""])[0]
    if not code or len(code) > 4096:
        raise ChatGPTAuthError("missing authorization code")
    if prior_client:
        if issued and issued != prior_client:
            raise ChatGPTAuthError("returning account client ID changed")
        issued = prior_client
    elif not issued or issued == "dynamic_agent_client":
        raise ChatGPTAuthError("dynamic client registration did not return issued client ID")
    return code, issued


def login(
    *,
    account_id: str | None = None,
    new: bool = False,
    root: Path | None = None,
    open_browser=webbrowser.open,
    timeout_seconds: float = 300,
) -> dict:
    """Authorize this host interactively; never emit tokens or callback codes."""
    if account_id and new:
        raise ChatGPTAuthError("choose either an existing --account or --new")
    home = root or state_dir()
    stable_host = host_id(home)
    previous = None if new or not accounts(home) else _choose(account_id, home)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    outcome: dict = {}

    class Callback(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            return  # Authorization code and ID tokens must not enter access logs.

        def do_GET(self):
            url = parse.urlsplit(self.path)
            if url.path != CALLBACK_PATH or len(self.path) > 8192:
                self.send_error(404)
                return
            outcome["query"] = url.query
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(
                b"ChatGPT sign-in callback received. Return to the HorusScan terminal."
            )

    with HTTPServer(("127.0.0.1", 0), Callback) as server:
        redirect = f"http://127.0.0.1:{server.server_port}{CALLBACK_PATH}"
        client_id = previous["client_id"] if previous else "dynamic_agent_client"
        params = {
            "client_id": client_id,
            "ext_agent_host_id": stable_host,
            "response_type": "code",
            "redirect_uri": redirect,
            "scope": SCOPES,
            "resource": RESOURCE,
            "state": state,
            "nonce": nonce,
            "code_challenge_method": "S256",
            "code_challenge": challenge,
        }
        if previous:
            if previous.get("id_token"):
                params["id_token_hint"] = previous["id_token"]
            if previous.get("email"):
                params["login_hint"] = previous["email"]
        else:
            params["agent_name_hint"] = APP_NAME
        url = AUTH_URL + "?" + parse.urlencode(params)
        if not open_browser(url):
            raise ChatGPTAuthError(
                "could not open a local system browser for ChatGPT authorization"
            )
        deadline = time.monotonic() + timeout_seconds
        while "query" not in outcome and time.monotonic() < deadline:
            server.timeout = min(1.0, max(0.1, deadline - time.monotonic()))
            server.handle_request()
    if "query" not in outcome:
        raise ChatGPTAuthError("ChatGPT sign-in callback timed out")
    code, issued = _callback_values(
        outcome["query"], state, previous["client_id"] if previous else None
    )
    tokens = _post_form(TOKEN_URL, {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": issued,
        "redirect_uri": redirect,
        "code_verifier": verifier,
        "resource": RESOURCE,
    })
    if not isinstance(tokens.get("id_token"), str):
        raise ChatGPTAuthError("missing signed identity token")
    claims = verify_id_token(tokens["id_token"], issued, nonce)
    if previous and claims["sub"] != previous["subject"]:
        raise ChatGPTAuthError("re-authorized ChatGPT account identity changed")
    record = _record(tokens, issued, claims, stable_host)
    key = _profile_key(issued, claims["sub"])
    _write(_profile_path(key, home), record)
    return {
        "id": key, "email": record.get("email"), "client_id": issued,
        "plan_enabled": True,
    }


def _refresh(record: dict) -> dict:
    result = _post_form(TOKEN_URL, {
        "grant_type": "refresh_token",
        "client_id": record["client_id"],
        "refresh_token": record["refresh_token"],
        "resource": RESOURCE,
    })
    granted = set(str(result.get("scope", "")).split())
    if not REQUIRED_SCOPES.issubset(granted):
        raise ChatGPTAuthError("refreshed session lacks ChatGPT plan permissions")
    for field in ("access_token", "refresh_token"):
        if not isinstance(result.get(field), str) or not result[field]:
            raise ChatGPTAuthError(f"refresh missing replacement {field}")
    if result.get("id_token"):
        # Refresh token responses may include an ID token but no new nonce.
        # Existing identity remains tied to its *previously validated* record;
        # never adopt unverified identity metadata from an optional refresh ID token.
        result.pop("id_token")
    lifetime = result.get("expires_in")
    if not isinstance(lifetime, (int, float)) or lifetime <= 0:
        raise ChatGPTAuthError("invalid refreshed token lifetime")
    return {
        **record,
        "access_token": result["access_token"],
        "refresh_token": result["refresh_token"],
        "scopes": sorted(granted),
        "expires_at": time.time() + float(lifetime),
        "earliest_refresh_at": result.get("earliest_refresh_at"),
    }


def get_access_token(account_id: str | None = None, root: Path | None = None) -> str:
    home = root or state_dir()
    with _refresh_lock(home):
        record = _choose(account_id or os.environ.get("HORUSTRACE_CHATGPT_ACCOUNT"), home)
        if not REQUIRED_SCOPES.issubset(record.get("scopes", [])):
            raise ChatGPTAuthError("ChatGPT plan scopes missing; sign in again")
        if not record.get("access_token") or not record.get("refresh_token"):
            raise ChatGPTAuthError("not signed in; run 'horustrace chatgpt login'")
        if float(record.get("expires_at", 0)) <= time.time() + 120:
            record = _refresh(record)
            _write(_profile_path(record["_local_id"], home),
                   {k: v for k, v in record.items() if k != "_local_id"})
        return record["access_token"]


def models(account_id: str | None = None, root: Path | None = None) -> list[dict]:
    token = get_access_token(account_id, root)
    req = request.Request(RESOURCE + "/models",
                          headers={"Authorization": "Bearer " + token})
    try:
        with request.urlopen(req, timeout=30) as response:
            raw = response.read(MAX_OAUTH_BYTES + 1)
    except error.HTTPError as exc:
        raise ChatGPTAuthError(f"ChatGPT model catalog HTTP {exc.code}") from exc
    except (error.URLError, TimeoutError) as exc:
        raise ChatGPTAuthError("ChatGPT model catalog unavailable") from exc
    if len(raw) > MAX_OAUTH_BYTES:
        raise ChatGPTAuthError("ChatGPT model catalog too large")
    data = json.loads(raw)
    if not isinstance(data.get("models"), list):
        raise ChatGPTAuthError("invalid ChatGPT model catalog")
    return [
        {"slug": row["slug"], "display_name": row.get("display_name", row["slug"])}
        for row in data["models"]
        if isinstance(row, dict) and row.get("visibility") == "list"
        and isinstance(row.get("slug"), str) and row["slug"]
    ]


def _revocation_endpoint() -> str:
    """Use the issuer's advertised revocation endpoint, never an arbitrary URL."""
    req = request.Request(DISCOVERY_URL)
    try:
        with request.urlopen(req, timeout=30) as response:
            raw = response.read(MAX_OAUTH_BYTES + 1)
    except (error.HTTPError, error.URLError, TimeoutError) as exc:
        raise ChatGPTAuthError("ChatGPT revocation discovery failed") from exc
    if len(raw) > MAX_OAUTH_BYTES:
        raise ChatGPTAuthError("ChatGPT revocation discovery too large")
    config = json.loads(raw)
    if not isinstance(config, dict) or config.get("issuer") != ISSUER:
        raise ChatGPTAuthError("untrusted ChatGPT revocation issuer")
    url = config.get("revocation_endpoint")
    parsed = parse.urlsplit(url) if isinstance(url, str) else None
    if (not parsed or parsed.scheme != "https"
            or parsed.hostname != "auth.openai.com"
            or parsed.port not in (None, 443)
            or not parsed.path.startswith("/api/accounts/")
            or parsed.username or parsed.password or parsed.query or parsed.fragment):
        raise ChatGPTAuthError("untrusted ChatGPT revocation endpoint")
    return url


def smoke(model: str, account_id: str | None = None, root: Path | None = None) -> dict:
    """User-invoked single-response account and model smoke test.

    Does not print, store, or return bearer tokens or model output. Runs only
    after user action through a local user-controlled runtime.
    """
    from horustrace.chatgpt_plan import ChatGPTPlanError, stream_responses
    from horustrace.llm_semantics import LLMSemanticError, _openai_text

    if not model or not model.strip():
        raise ChatGPTAuthError("select a model slug from 'horustrace chatgpt models'")
    catalog = models(account_id, root)
    if model not in {entry["slug"] for entry in catalog}:
        raise ChatGPTAuthError("selected model is not in this ChatGPT account catalog")

    token = get_access_token(account_id, root)
    try:
        response = stream_responses({
            "model": model,
            "input": [{
                "role": "user",
                "content": "Authentication smoke test. Reply with exactly: ready",
            }],
        }, token)
        output, request_id = _openai_text(response)
    except (ChatGPTPlanError, LLMSemanticError) as exc:
        # Preserve only sanitized model-transport error descriptions.
        raise ChatGPTAuthError(str(exc)) from exc
    if output.strip().lower() != "ready":
        raise ChatGPTAuthError("the model completed but did not return expected smoke text")
    return {
        "status": "completed",
        "provider": "chatgpt_plan",
        "model": model,
        "request_id": request_id,
        "result": "ready",
    }


def logout(account_id: str | None = None, root: Path | None = None) -> dict:
    home = root or state_dir()
    with _refresh_lock(home):
        record = _choose(account_id, home)
        revoked = False
        if record.get("refresh_token"):
            values = {
                "client_id": record["client_id"],
                "token": record["refresh_token"],
                "token_type_hint": "refresh_token",
            }
            try:
                body = parse.urlencode(values).encode("utf-8")
                req = request.Request(
                    _revocation_endpoint(), data=body, method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                with request.urlopen(req, timeout=30) as response:
                    revoked = response.status == 200
            except (error.HTTPError, error.URLError, TimeoutError, ChatGPTAuthError):
                pass
        for field in ("access_token", "refresh_token", "id_token"):
            record.pop(field, None)
        _write(_profile_path(record["_local_id"], home),
               {k: v for k, v in record.items() if k != "_local_id"})
        return {"id": record["_local_id"], "remote_revocation_confirmed": revoked}
