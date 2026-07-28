"""SSO2OAUTH 9-phase flow with curl_cffi.

Called by sso2oauthd.py (the daemon). Replicates the Go SSO2OAUTH
conversion flow from internal/infra/provider/web/sso_build.go using
curl_cffi's chrome136 TLS fingerprint, which Go's tls-client cannot
emulate (uTLS != BoringSSL; CF JS challenge requires BoringSSL).

Header construction is a 1:1 port of internal/infra/provider/xaiauth/headers.go;
bot classification is a 1:1 port of jwt.go ClassifyConvertBot.

See 修改计划.md §16.4 for the Go<->Python data contract.
"""
import json
import time
import uuid
import hashlib
import base64

# ============================================================
# Constants — port of xaiauth/headers.go:14-44
# ============================================================
CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
DEFAULT_SCOPE = "openid profile email offline_access grok-cli:access api:access conversations:read conversations:write workspaces:read workspaces:write"
DEFAULT_CLI_VERSION = "0.2.111"
DEFAULT_BROWSER_UA = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.0 Mobile Safari/537.36"
DEVICE_REFERRER = "grok-build"
SURFACE_UI = "ui"
TOKEN_AUTH_VALUE = "xai-grok-cli"

AUTH_BASE = "https://auth.x.ai"
ACCOUNTS_BASE = "https://accounts.x.ai"
CLI_PROXY_BASE = "https://cli-chat-proxy.grok.com"
XAI_BASE = "https://x.ai"

DEVICE_CODE_URL = f"{AUTH_BASE}/oauth2/device/code"
TOKEN_URL = f"{AUTH_BASE}/oauth2/token"
VERIFY_URL = f"{AUTH_BASE}/oauth2/device/verify"
APPROVE_URL = f"{AUTH_BASE}/oauth2/device/approve"
USER_URL = f"{CLI_PROXY_BASE}/v1/user"
SETTINGS_URL = f"{CLI_PROXY_BASE}/v1/settings"
MODELS_URL = f"{CLI_PROXY_BASE}/v1/models"
BUNDLE_URL = f"{CLI_PROXY_BASE}/v1/bundle/archive"
BILLING_URL = f"{CLI_PROXY_BASE}/v1/billing?format=credits"
SUBSCRIPTION_URL = f"{CLI_PROXY_BASE}/v1/user?include=subscription"
LOGIN_CONFIG_URL = f"{CLI_PROXY_BASE}/v1/login-config"
CLI_STABLE_URL = f"{XAI_BASE}/cli/stable"
CHANGELOGS_JSON_URL = f"{XAI_BASE}/cli/changelogs/{DEFAULT_CLI_VERSION}.external.json"
CHANGELOGS_MD_URL = f"{XAI_BASE}/cli/changelogs/{DEFAULT_CLI_VERSION}.external.md"
RATE_LIMITS_URL = "https://grok.com/rest/rate-limits"
FEEDBACK_CONFIG_URL = f"{CLI_PROXY_BASE}/v1/feedback/config"
MCP_TOOLS_LIST_URL = f"{CLI_PROXY_BASE}/v1/mcp/tools/list"

# curl_cffi impersonation targets. chrome136 is required for
# cli-chat-proxy / auth / accounts (CF JS challenge fingerprints the
# BoringSSL TLS stack). chrome120 is used for grok.com/rest/rate-limits
# per reference capture (sso2oauth.py uses chrome120 for this endpoint).
IMP = "chrome136"
IMP_RATE_LIMITS = "chrome120"
BODY_PREVIEW_LEN = 512

# Rate-limits endpoint uses a browser UA (Windows Chrome), not the CLI
# dual-UA, per reference capture.
RATE_LIMITS_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36"


# ============================================================
# JWT / identity — port of xaiauth/jwt.go
# ============================================================
def stable_agent_id(sso_token):
    """Port of xaiauth.StableAgentIDFromSSO (jwt.go:138-150).
    UUID5(NameSpaceURL, "grok2api:grok-cli-agent:" + seed) where
    seed = session_id claim, or sha256(token) if absent.
    """
    sso_token = (sso_token or "").strip()
    if not sso_token:
        return ""
    claims = _decode_jwt_claims(sso_token)
    seed_val = (claims or {}).get("session_id")
    # ClaimString coerces numbers/bools to string; match Go semantics.
    if seed_val is None:
        seed = ""
    elif isinstance(seed_val, bool):
        seed = "true" if seed_val else "false"
    elif isinstance(seed_val, (int, float)):
        seed = _stringify_number(seed_val)
    else:
        seed = str(seed_val).strip()
    if not seed:
        seed = hashlib.sha256(sso_token.encode("utf-8")).hexdigest()
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "grok2api:grok-cli-agent:" + seed))


def _stringify_number(n):
    """Match Go ClaimString: integers as int, floats as compact."""
    if isinstance(n, float) and n == int(n):
        return str(int(n))
    if isinstance(n, float):
        # Go strconv.FormatFloat(f, 'f', -1, 64) — shortest round-trip
        return repr(n) if "e" in repr(n) else str(n)
    return str(n)


def _decode_jwt_claims(token):
    """Port of xaiauth.DecodeClaims (jwt.go:16-35). No signature verify."""
    token = token or ""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    payload = parts[1]
    # Go: try RawURLEncoding first, then padded URLEncoding.
    try:
        data = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    except Exception:
        try:
            padded = payload + "=" * ((4 - len(payload) % 4) % 4)
            data = base64.urlsafe_b64decode(padded)
        except Exception:
            return None
    try:
        return json.loads(data)
    except Exception:
        return None


def _claim_string(claims, key):
    """Port of xaiauth.ClaimString (jwt.go:38-64)."""
    if not claims:
        return ""
    val = claims.get(key)
    if val is None:
        return ""
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, (int, float)):
        return _stringify_number(val).strip()
    if isinstance(val, str):
        return val.strip()
    return str(val).strip()


def _classify_convert_bot(access_claims):
    """Port of xaiauth.ClassifyConvertBot (jwt.go:100-134).
    Returns (class, raw) where class is one of:
    "clean" | "contaminated" | "super_signal".
    """
    if not access_claims:
        return "clean", ""
    raw = access_claims.get("bot_flag_source")
    if raw is None:
        return "clean", ""
    # bool must be checked BEFORE int — Python bool subclasses int.
    # Go's type switch sends bool to `default` (not `case float64`),
    # where only "" and "NP" are clean; all other strings are
    # contaminated. So both True and False → contaminated.
    if isinstance(raw, bool):
        s = "true" if raw else "false"
        return "contaminated", s
    if isinstance(raw, (int, float)):
        if raw == 1:
            return "super_signal", "1"
        if raw == 0:
            return "clean", "0"
        return "contaminated", _stringify_number(raw)
    if isinstance(raw, str):
        trimmed = raw.strip()
        if trimmed == "" or trimmed.upper() == "NP":
            return "clean", trimmed
        if trimmed == "1":
            # Go: ambiguous string "1" treated as super_signal for convert gate.
            return "super_signal", trimmed
        return "contaminated", trimmed
    s = str(raw).strip()
    if s == "" or s.upper() == "NP":
        return "clean", s
    return "contaminated", s


# ============================================================
# Header construction — port of xaiauth/headers.go
# ============================================================
def dual_cli_ua(version):
    """Port of xaiauth.DualCLIUserAgent (headers.go:47-53)."""
    version = (version or "").strip() or DEFAULT_CLI_VERSION
    return f"grok-pager/{version} grok-shell/{version} (linux; aarch64)"


def cli_form_headers(version, surface=""):
    """Port of xaiauth.ApplyCLIAuthForm (headers.go:65-97).
    For device/code + token poll form POSTs.
    """
    version = (version or "").strip() or DEFAULT_CLI_VERSION
    h = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, br, deflate",
        "User-Agent": dual_cli_ua(version),
    }
    if surface:
        h["x-grok-client-surface"] = surface
        h["x-grok-client-version"] = version
    return h


def browser_html_headers(ua, step, user_code="", referer=""):
    """Port of xaiauth.ApplyBrowserAuthHTML (headers.go:127-172).
    For accounts verify/approve HTML navigation.
    """
    ua = (ua or "").strip() or DEFAULT_BROWSER_UA
    user_code = (user_code or "").strip()
    referer = (referer or "").strip()
    h = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": ua,
    }
    if step == "verify_page":
        h["Referer"] = "https://accounts.x.ai/oauth2/device"
    elif step == "verify":
        h["Content-Type"] = "application/x-www-form-urlencoded"
        h["Origin"] = "https://accounts.x.ai"
        h["Referer"] = (
            f"https://accounts.x.ai/oauth2/device?user_code={user_code}"
            if user_code
            else "https://accounts.x.ai/oauth2/device"
        )
    elif step == "consent":
        h["Referer"] = "https://auth.x.ai/oauth2/device/verify"
    elif step == "approve":
        h["Content-Type"] = "application/x-www-form-urlencoded"
        h["Origin"] = "https://accounts.x.ai"
        if referer:
            h["Referer"] = referer
        elif user_code:
            h["Referer"] = f"https://accounts.x.ai/oauth2/device/consent?user_code={user_code}"
        else:
            h["Referer"] = "https://accounts.x.ai/"
    elif step in ("accounts", "document"):
        h["Referer"] = "https://accounts.x.ai/"
    return h


def cli_api_headers(access_token, version):
    """Port of xaiauth.ApplyCLIApiMeta (headers.go:175-192).
    Authenticated cli-chat-proxy API headers (GET /v1/user etc).
    """
    version = (version or "").strip() or DEFAULT_CLI_VERSION
    h = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, br, deflate",
        "User-Agent": dual_cli_ua(version),
        "x-grok-client-version": version,
        "x-grok-client-mode": "interactive",
        "x-xai-token-auth": TOKEN_AUTH_VALUE,
    }
    if access_token and access_token.strip():
        h["Authorization"] = f"Bearer {access_token}"
    return h


def cli_enrichment_headers(access_token, version, opts):
    """Port of xaiauth.ApplyCLIEnrichmentHeaders (headers.go:204-221).
    Extends CLIApiMeta with x-userid/x-email/agent/identifier.
    """
    h = cli_api_headers(access_token, version)
    if opts.get("user_id"):
        h["x-userid"] = opts["user_id"]
    if opts.get("email"):
        h["x-email"] = opts["email"]
    if opts.get("agent_id"):
        h["x-grok-agent-id"] = opts["agent_id"]
    if opts.get("include_shell_identifier"):
        h["x-grok-client-identifier"] = "grok-shell"
    return h


def login_config_headers(version, agent_id):
    """Port of xaiauth.ApplyLoginConfigHeaders (headers.go:225-245).
    Unauthenticated; identifier grok-shell; no Bearer.
    """
    version = (version or "").strip() or DEFAULT_CLI_VERSION
    h = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, br, deflate",
        "User-Agent": dual_cli_ua(version),
        "x-grok-client-version": version,
        "x-grok-client-mode": "interactive",
        "x-grok-client-identifier": "grok-shell",
    }
    if agent_id and agent_id.strip():
        h["x-grok-agent-id"] = agent_id
    return h


def cli_probe_headers():
    """Port of xaiauth.ApplyCLIProbeHeaders (headers.go:248-254).
    Minimal headers for GET x.ai/cli/stable.
    """
    return {"Accept": "*/*", "Accept-Encoding": "gzip, br, deflate"}


# ============================================================
# Phase trace — redaction per §16.4 contract
# ============================================================
def trace(name, method, response):
    """Build a PhaseTrace dict, redacting the Cookie request header
    and truncating the response body to 512 chars.
    """
    req_headers = {}
    req = getattr(response, "request", None)
    if req and getattr(req, "headers", None):
        for k, v in req.headers.items():
            if k.lower() in ("cookie", "authorization"):
                req_headers[k] = "[redacted]"
            else:
                req_headers[k] = v
    resp_headers = {}
    for k, v in (response.headers or {}).items():
        resp_headers[k] = v
    body_preview = (response.text or "")[:BODY_PREVIEW_LEN]
    return {
        "name": name,
        "request": {
            "method": method,
            "url": str(response.url) if hasattr(response, "url") else "",
            "headers": req_headers,
            "body": None,
        },
        "response": {
            "status": response.status_code,
            "headers": resp_headers,
            "body_preview": body_preview,
        },
    }


# ============================================================
# Main flow — port of web/sso_build.go ConvertToBuild (line 55+)
# ============================================================
def convert(req):
    """Run the 9-phase SSO→OAuth conversion. Returns a dict matching
    ConvertResponse (§16.4): {ok:true,...} on success, {ok:false,...} on
    failure with error_phase/status/message/url and phases trace.
    """
    sso = req.get("sso_token", "") or ""
    proxy = req.get("proxy_url", "") or ""
    proxy_pool = req.get("proxy_pool") or []
    if proxy and proxy not in proxy_pool:
        proxy_pool.insert(0, proxy)
    ua = req.get("user_agent", "") or DEFAULT_BROWSER_UA
    cf_cookies = req.get("cf_cookies", "") or ""
    cli_ver = req.get("cli_version", "") or DEFAULT_CLI_VERSION
    timeout_seconds = req.get("timeout_seconds") or 30
    opts = req.get("options", {}) or {}
    agent_id = stable_agent_id(sso)

    if not sso:
        return {
            "ok": False,
            "error_phase": "invalid_request",
            "error_status": 0,
            "error_message": "missing sso_token",
            "error_url": "",
            "phases": [],
        }

    from curl_cffi.requests import Session

    # Try each proxy in the pool; on connection error rotate to next.
    last_exc = None
    for pi, proxy_url in enumerate(proxy_pool or [proxy or ""]):
        if not proxy_url:
            continue
        s = Session(impersonate=IMP)
        if proxy_url:
            s.proxies = {"http": proxy_url, "https": proxy_url}
        s.cookies.set("sso", sso, domain=".x.ai", path="/")
        s.cookies.set("sso-rw", sso, domain=".x.ai", path="/")
        if cf_cookies:
            for kv in cf_cookies.split("; "):
                k, sep, v = kv.partition("=")
                if k.strip() and sep:
                    s.cookies.set(k.strip(), v.strip(), domain=".x.ai", path="/")

        phases = []
        try:
            return _run_flow(s, ua, cli_ver, agent_id, opts, phases, sso, proxy_url, timeout_seconds)
        except Exception as e:
            s.close()
            last_exc = e
            # If there are more proxies to try, continue (only for connection-level errors)
            err_str = str(e).lower()
            if pi < len(proxy_pool) - 1 and ("timeout" in err_str or "connection" in err_str or "refused" in err_str or "resolve" in err_str):
                continue
            break

    return {
        "ok": False,
        "error_phase": "exception",
        "error_status": 0,
        "error_message": str(last_exc or "all proxies failed"),
        "error_url": "",
        "phases": phases,
    }


def _run_flow(s, ua, cli_ver, agent_id, opts, phases, sso, proxy, timeout_seconds=30):
    """Phases 00a→06. Mirrors sso2oauth.py reference capture order."""

    # Phase 00a: Rate Limits — POST grok.com/rest/rate-limits.
    # Uses an independent chrome120 session with browser UA + SSO cookie
    # in the header (not session cookies). Failure aborts the flow.
    # Reference: sso2oauth.py:377-408.
    rl_session = None
    try:
        from curl_cffi.requests import Session as RLSession
        rl_session = RLSession(impersonate=IMP_RATE_LIMITS)
        if proxy:
            rl_session.proxies = {"http": proxy, "https": proxy}
    except Exception:
        pass
    rate_limits = None
    if rl_session is not None:
        rl_headers = {
            "accept": "*/*",
            "content-type": "application/json",
            "origin": "https://grok.com",
            "user-agent": RATE_LIMITS_UA,
            "cookie": f"sso={sso}",
        }
        rl_body = {"requestKind": "DEFAULT", "modelName": "grok-3"}
        try:
            r = rl_session.post(RATE_LIMITS_URL, headers=rl_headers, json=rl_body, timeout=timeout_seconds)
            phases.append(trace("00a-rate-limits", "POST", r))
            if r.status_code >= 400:
                return _fail("rate_limits", r, phases)
            try:
                rl_data = r.json()
                rate_limits = {
                    "remaining_queries": rl_data.get("remainingQueries"),
                    "total_queries": rl_data.get("totalQueries"),
                    "window_seconds": rl_data.get("windowSizeSeconds"),
                }
            except Exception:
                pass
        finally:
            rl_session.close()

    # Phase 00: probe accounts.x.ai — warms up __cf_bm cookie for the
    # CF-protected accounts subdomain. Go's tls-client gets 403 here;
    # curl_cffi chrome136 gets 200 (verified 2026-07-22).
    r = s.get(f"{ACCOUNTS_BASE}/", headers=browser_html_headers(ua, "accounts"),
              timeout=timeout_seconds * 2, allow_redirects=True)
    phases.append(trace("00-probe", "GET", r))
    if r.status_code >= 400:
        return _fail("probe_accounts", r, phases)

    # Phase 01: CLI stable version. Always executed (reference capture
    # sso2oauth.py:413-422 treats this as mandatory; failure aborts).
    r = s.get(CLI_STABLE_URL, headers=cli_probe_headers(), timeout=timeout_seconds)
    phases.append(trace("01-cli-version", "GET", r))
    if r.status_code >= 400:
        return _fail("cli_version", r, phases)

    # Phase 02: login-config. Always executed (reference capture
    # sso2oauth.py:427-447 treats this as mandatory; failure aborts).
    r = s.get(LOGIN_CONFIG_URL, headers=login_config_headers(cli_ver, agent_id),
              timeout=timeout_seconds)
    phases.append(trace("02-login-config", "GET", r))
    if r.status_code >= 400:
        return _fail("login_config", r, phases)

    # Phase 03: OIDC discovery.
    r = s.get(f"{AUTH_BASE}/.well-known/openid-configuration",
              headers={"Accept": "*/*"}, timeout=timeout_seconds)
    phases.append(trace("03-oidc-discovery", "GET", r))
    if r.status_code >= 400:
        return _fail("oidc_discovery", r, phases)

    # Phase 04: device/code.
    r = s.post(DEVICE_CODE_URL,
               data={"client_id": CLIENT_ID, "scope": DEFAULT_SCOPE, "referrer": DEVICE_REFERRER},
               headers=cli_form_headers(cli_ver, surface=SURFACE_UI),
               timeout=timeout_seconds)
    phases.append(trace("04-device-code", "POST", r))
    if r.status_code >= 400:
        return _fail("device_code", r, phases)
    dev = r.json()
    uc = dev.get("user_code", "")
    dc = dev.get("device_code", "")
    vc = dev.get("verification_uri_complete", "")
    interval = dev.get("interval") or 5
    if not (uc and dc and vc):
        return _fail("device_code", r, phases,
                     msg=f"device code response incomplete: uc={uc!r} dc={dc!r} vc={vc!r}")
    if interval <= 0:
        interval = 5

    # Phase 04a: verify page (GET verification_uri_complete).
    r = s.get(vc, headers=browser_html_headers(ua, "verify_page", uc),
              timeout=timeout_seconds * 2, allow_redirects=True)
    phases.append(trace("04a-verify-page", "GET", r))
    if r.status_code >= 400:
        return _fail("verify_page", r, phases)

    # Phase 04b-1: POST verify (form-encoded user_code).
    # Follow redirects manually via Location header (reference sso2oauth.py:565-597).
    r = s.post(VERIFY_URL, data={"user_code": uc},
               headers=browser_html_headers(ua, "verify", uc),
               timeout=timeout_seconds * 2, allow_redirects=False)
    phases.append(trace("04b-device-verify", "POST", r))
    if r.status_code not in (302, 303):
        return _fail("device_verify", r, phases)
    consent_url = r.headers.get("Location", "") or ""

    # Phase 04b-2: GET consent page if redirected there (reference sso2oauth.py:577-597).
    if consent_url:
        r = s.get(consent_url, headers=browser_html_headers(ua, "consent", uc),
                  timeout=timeout_seconds * 2, allow_redirects=True)
        phases.append(trace("04b-consent-page", "GET", r))
    # No consent redirect → account may have pre-approved consent; proceed to approve.

    # Phase 04c: POST approve. Reference sso2oauth.py:619-627 —
    # allow_redirects=False, check 302/303, don't follow redirect.
    r = s.post(APPROVE_URL,
               data={"user_code": uc, "action": "allow",
                     "principal_type": "User", "principal_id": ""},
               headers=browser_html_headers(ua, "approve", uc, consent_url),
               timeout=timeout_seconds * 2, allow_redirects=False)
    phases.append(trace("04c-device-approve", "POST", r))
    if r.status_code not in (302, 303):
        return _fail("device_approve", r, phases)

    # Phase 05: token poll. Go uses ExpiresIn * Interval; the reference
    # script polls 2x@5s; we poll up to 15x@interval (more robust for
    # batch convert scenarios where approval latency varies).
    # Phase 05: token poll. Reference sso2oauth.py:648-699 — 2 polls × 5s.
    for i in range(5):
        time.sleep(interval)
        r = s.post(TOKEN_URL,
                   data={"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                         "device_code": dc, "client_id": CLIENT_ID},
                   headers=cli_form_headers(cli_ver, surface=SURFACE_UI),
                   timeout=timeout_seconds)
        phases.append(trace("05-token-poll", "POST", r))
        if r.status_code == 200:
            tok = r.json()
            identity, bot_flag, enrichment = _run_enrichment(
                s, tok["access_token"], tok.get("id_token", ""),
                cli_ver, agent_id, opts, phases, timeout_seconds)
            if rate_limits:
                enrichment["rate_limits"] = rate_limits
            return {
                "ok": True,
                "tokens": {
                    "access_token": tok.get("access_token", ""),
                    "refresh_token": tok.get("refresh_token", ""),
                    "id_token": tok.get("id_token", ""),
                    "expires_in": tok.get("expires_in", 0),
                    "token_type": tok.get("token_type", "Bearer"),
                    "scope": tok.get("scope", ""),
                },
                "identity": identity,
                "bot_flag": bot_flag,
                "enrichment": enrichment,
                "phases": phases,
            }
        try:
            err = r.json().get("error", "unknown")
        except Exception:
            err = f"non-json-http-{r.status_code}"
        if err != "authorization_pending":
            return _fail("token_poll", r, phases,
                         msg=f"token poll error: {err}")
    phases.append(trace("05-token-poll-timeout", "POST", r))
    return {
        "ok": False,
        "error_phase": "token_poll_timeout",
        "error_status": 0,
        "error_message": f"Token poll 超时 ({5 * interval}s)",
        "error_url": TOKEN_URL,
        "phases": phases,
    }


def _run_enrichment(s, access_token, id_token, cli_ver, agent_id, opts, phases, timeout_seconds=30):
    """Phase 05a-06: user → settings → models → bundle → billing →
    changelogs → subscription → pre-flight.
    Fail-open (non-2xx does not abort). Port of sso2oauth.py:710-876.
    Returns (identity, bot_flag, enrichment).
    """
    identity = {"user_id": "", "email": "", "team_id": ""}
    bot_flag = {"class": "clean", "raw": ""}
    # Enrichment keys are only set when populated with real data.
    # Initializing to None would serialize as JSON null, which Go's
    # json.RawMessage captures as 4-byte "null" (len>0), causing
    # ParseBilling to silently return a zero-value Billing{} that
    # overwrites real data in the database.
    enrichment = {"models": []}

    # Pre-populate identity from token claims (Go IdentityFromTokens).
    access_claims = _decode_jwt_claims(access_token)
    id_claims = _decode_jwt_claims(id_token) if id_token else None
    identity["user_id"] = _claim_string(access_claims, "sub") or _claim_string(id_claims, "sub")
    identity["email"] = _claim_string(id_claims, "email") or _claim_string(access_claims, "email")
    identity["team_id"] = _claim_string(access_claims, "team_id") or _claim_string(id_claims, "team_id")

    # Bot flag classification (needed for pre-flight skip decision).
    bot_class, bot_raw = _classify_convert_bot(access_claims)
    bot_flag = {"class": bot_class, "raw": bot_raw}

    if opts.get("skip_init_user"):
        return identity, bot_flag, enrichment

    enrich = {"agent_id": agent_id, "include_shell_identifier": True}

    # 05a-1: GET /v1/user — base auth headers (no enrichment fields yet).
    r = s.get(USER_URL, headers=cli_api_headers(access_token, cli_ver), timeout=timeout_seconds)
    phases.append(trace("05a-init-user", "GET", r))
    if r.status_code < 300:
        try:
            data = r.json()
        except Exception:
            data = {}
        uid = (data.get("userId") or "").strip()
        em = (data.get("email") or "").strip()
        tid = (data.get("teamId") or "").strip()
        if uid:
            identity["user_id"] = uid
            enrich["user_id"] = uid
        if em:
            identity["email"] = em
            enrich["email"] = em
        if tid:
            identity["team_id"] = tid

    # 05a-2: GET /v1/user (repeat — consistency check per reference capture).
    r = s.get(USER_URL, headers=cli_api_headers(access_token, cli_ver), timeout=timeout_seconds)
    phases.append(trace("05a-user-repeat", "GET", r))

    # 05b: settings (enrichment headers with user_id/email/agent/shell).
    r = s.get(SETTINGS_URL, headers=cli_enrichment_headers(access_token, cli_ver, enrich),
              timeout=timeout_seconds)
    phases.append(trace("05b-settings", "GET", r))

    # 05c: models.
    r = s.get(MODELS_URL, headers=cli_enrichment_headers(access_token, cli_ver, enrich),
              timeout=timeout_seconds)
    phases.append(trace("05c-models", "GET", r))
    if r.status_code < 300:
        try:
            mj = r.json()
            if isinstance(mj, list):
                enrichment["models"] = [m.get("id", "") for m in mj if isinstance(m, dict)]
            elif isinstance(mj, dict):
                data_list = mj.get("data", [])
                enrichment["models"] = [m.get("id", "") for m in data_list if isinstance(m, dict)]
        except Exception:
            pass

    # 05d: bundle/archive.
    r = s.get(BUNDLE_URL, headers=cli_enrichment_headers(access_token, cli_ver, enrich),
              timeout=timeout_seconds)
    phases.append(trace("05d-bundle", "GET", r))

    # 05e: billing — capture parsed JSON for Go ParseBilling.
    # Must store as dict (not r.text string) so json.RawMessage on the
    # Go side receives a JSON object, not a JSON string.
    r = s.get(BILLING_URL, headers=cli_enrichment_headers(access_token, cli_ver, enrich),
              timeout=timeout_seconds)
    phases.append(trace("05e-billing", "GET", r))
    if r.status_code < 300:
        try:
            enrichment["billing_raw"] = r.json()
        except Exception:
            pass

    # 05f: changelogs (json + md). No auth; different domain.
    # Reference capture: sso2oauth.py:817-828.
    changelog_h = {"accept": "*/*", "accept-encoding": "gzip, br, deflate"}
    r = s.get(CHANGELOGS_JSON_URL, headers=changelog_h, timeout=timeout_seconds)
    phases.append(trace("05f-changelog-json", "GET", r))
    r = s.get(CHANGELOGS_MD_URL, headers=changelog_h, timeout=timeout_seconds)
    phases.append(trace("05f-changelog-md", "GET", r))

    # 05g: subscription — 5s delay before request (reference capture
    # sso2oauth.py:832). Go uses EnrichmentOptions{AgentID: f.agentID}
    # (only agent_id, no user_id/email/shell-identifier).
    time.sleep(5)
    r = s.get(SUBSCRIPTION_URL,
              headers=cli_enrichment_headers(access_token, cli_ver, {"agent_id": agent_id}),
              timeout=timeout_seconds)
    phases.append(trace("05g-subscription", "GET", r))
    if r.status_code < 300:
        try:
            enrichment["subscription_raw"] = r.json()
        except Exception:
            pass
        try:
            data = r.json()
        except Exception:
            data = {}
        uid = (data.get("userId") or "").strip()
        em = (data.get("email") or "").strip()
        tid = (data.get("teamId") or "").strip()
        if uid:
            identity["user_id"] = uid
        if em:
            identity["email"] = em
        if tid:
            identity["team_id"] = tid

    # Phase 06: Pre-flight — skipped if bot contaminated.
    # Reference capture: sso2oauth.py:845-876.
    if bot_class != "contaminated":
        pf_h = cli_api_headers(access_token, cli_ver)
        # 06a: GET /v1/feedback/config
        r = s.get(FEEDBACK_CONFIG_URL, headers=pf_h, timeout=timeout_seconds)
        phases.append(trace("06a-feedback-config", "GET", r))
        # 06b: GET /v1/mcp/tools/list
        r = s.get(MCP_TOOLS_LIST_URL, headers=pf_h, timeout=timeout_seconds)
        phases.append(trace("06b-mcp-tools-list", "GET", r))
        # 06c: GET /v1/billing?format=credits (pre-flight, with x-userid)
        pf_bill_h = dict(pf_h)
        if enrich.get("user_id"):
            pf_bill_h["x-userid"] = enrich["user_id"]
        r = s.get(BILLING_URL, headers=pf_bill_h, timeout=timeout_seconds)
        phases.append(trace("06c-billing-preflight", "GET", r))

    return identity, bot_flag, enrichment


def _fail(phase, response, phases, msg=None):
    """Build a failure ConvertResponse dict."""
    status = response.status_code if response is not None else 0
    url = str(response.url) if response is not None and hasattr(response, "url") else ""
    if msg is None:
        msg = f"sso2oauth[{phase}] 失败 status={status}"
    return {
        "ok": False,
        "error_phase": phase,
        "error_status": status,
        "error_message": msg,
        "error_url": url,
        "phases": phases,
    }
