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

# curl_cffi impersonation target. chrome136 is required because CF's
# JS challenge fingerprints the BoringSSL TLS stack; only curl_cffi's
# chrome136 build carries the matching ClientHello + ALPS + grease.
IMP = "chrome136"
BODY_PREVIEW_LEN = 512


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
    ua = req.get("user_agent", "") or DEFAULT_BROWSER_UA
    cf_cookies = req.get("cf_cookies", "") or ""
    cli_ver = req.get("cli_version", "") or DEFAULT_CLI_VERSION
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

    # Session-level impersonate (not per-request) — matches reference
    # script behavior; ensures consistent TLS fingerprint across all
    # phases. Headers passed per-request merge with session defaults.
    s = Session(impersonate=IMP)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    s.cookies.set("sso", sso, domain=".x.ai", path="/")
    s.cookies.set("sso-rw", sso, domain=".x.ai", path="/")
    if cf_cookies:
        for kv in cf_cookies.split("; "):
            k, sep, v = kv.partition("=")
            if k.strip() and sep:
                s.cookies.set(k.strip(), v.strip(), domain=".x.ai", path="/")

    phases = []
    try:
        return _run_flow(s, ua, cli_ver, agent_id, opts, phases)
    except Exception as e:
        return {
            "ok": False,
            "error_phase": "exception",
            "error_status": 0,
            "error_message": str(e),
            "error_url": "",
            "phases": phases,
        }


def _run_flow(s, ua, cli_ver, agent_id, opts, phases):
    """Phases 00→05g. Mirrors sso_build.go ConvertToBuild order."""

    # Phase 00: probe accounts.x.ai — warms up __cf_bm cookie for the
    # CF-protected accounts subdomain. Go's tls-client gets 403 here;
    # curl_cffi chrome136 gets 200 (verified 2026-07-22).
    r = s.get(f"{ACCOUNTS_BASE}/", headers=browser_html_headers(ua, "accounts"),
              timeout=30, allow_redirects=True)
    phases.append(trace("00-probe", "GET", r))
    if r.status_code >= 400:
        return _fail("probe_accounts", r, phases)

    # Phase 01: CLI stable version (soft preflight). Go skips this by
    # default too unless RecommendedBuildClientVersion is set.
    if opts.get("soft_preflight"):
        r = s.get(CLI_STABLE_URL, headers=cli_probe_headers(), timeout=15)
        phases.append(trace("01-cli-version", "GET", r))

    # Phase 02: login-config (soft preflight).
    if opts.get("soft_preflight"):
        r = s.get(LOGIN_CONFIG_URL, headers=login_config_headers(cli_ver, agent_id),
                  timeout=15)
        phases.append(trace("02-login-config", "GET", r))

    # Phase 03: OIDC discovery.
    r = s.get(f"{AUTH_BASE}/.well-known/openid-configuration",
              headers={"Accept": "*/*"}, timeout=15)
    phases.append(trace("03-oidc-discovery", "GET", r))
    if r.status_code >= 400:
        return _fail("oidc_discovery", r, phases)

    # Phase 04: device/code.
    r = s.post(DEVICE_CODE_URL,
               data={"client_id": CLIENT_ID, "scope": DEFAULT_SCOPE, "referrer": DEVICE_REFERRER},
               headers=cli_form_headers(cli_ver, surface=SURFACE_UI),
               timeout=15)
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
              timeout=30, allow_redirects=True)
    phases.append(trace("04a-verify-page", "GET", r))
    if r.status_code >= 400:
        return _fail("verify_page", r, phases)

    # Phase 04b-1: POST verify (form-encoded user_code).
    r = s.post(VERIFY_URL, data={"user_code": uc},
               headers=browser_html_headers(ua, "verify", uc),
               timeout=30, allow_redirects=False)
    phases.append(trace("04b-device-verify", "POST", r))
    if r.status_code not in (302, 303):
        return _fail("device_verify", r, phases)
    consent_url = r.headers.get("Location", "") or ""

    # Phase 04b-2: GET consent page (if redirect present).
    if consent_url:
        r = s.get(consent_url, headers=browser_html_headers(ua, "consent", uc),
                  timeout=30, allow_redirects=True)
        phases.append(trace("04b-consent-page", "GET", r))

    # Phase 04c: POST approve.
    r = s.post(APPROVE_URL,
               data={"user_code": uc, "action": "allow",
                     "principal_type": "User", "principal_id": ""},
               headers=browser_html_headers(ua, "approve", uc, consent_url),
               timeout=30, allow_redirects=False)
    phases.append(trace("04c-device-approve", "POST", r))
    if r.status_code not in (302, 303):
        return _fail("device_approve", r, phases)

    # Phase 05: token poll. Go uses ExpiresIn * Interval; the reference
    # script polls 2x@5s; we poll up to 15x@interval (more robust for
    # batch convert scenarios where approval latency varies).
    for _ in range(15):
        time.sleep(interval)
        r = s.post(TOKEN_URL,
                   data={"grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                         "device_code": dc, "client_id": CLIENT_ID},
                   headers=cli_form_headers(cli_ver, surface=SURFACE_UI),
                   timeout=15)
        try:
            tok = r.json()
        except Exception:
            tok = {}
        if "access_token" in tok:
            phases.append(trace("05-token-poll", "POST", r))
            identity, bot_flag = _run_enrichment(
                s, tok["access_token"], tok.get("id_token", ""),
                cli_ver, agent_id, opts, phases)
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
                "phases": phases,
            }
        err = tok.get("error", "")
        if err in ("expired_token", "access_denied"):
            phases.append(trace("05-token-poll", "POST", r))
            return _fail("token_poll", r, phases,
                         msg=f"token poll error: {err}")
    phases.append(trace("05-token-poll-timeout", "POST", r))
    return {
        "ok": False,
        "error_phase": "token_poll_timeout",
        "error_status": 0,
        "error_message": f"Token poll 超时 ({15 * interval}s)",
        "error_url": TOKEN_URL,
        "phases": phases,
    }


def _run_enrichment(s, access_token, id_token, cli_ver, agent_id, opts, phases):
    """Phase 05a-05g: user → settings → models → bundle → billing → subscription.
    Fail-open (non-2xx does not abort). Port of sso_build.go:runCLIEnrichment.
    """
    identity = {"user_id": "", "email": "", "team_id": ""}
    bot_flag = {"class": "clean", "raw": ""}

    # Pre-populate identity from token claims (Go IdentityFromTokens).
    access_claims = _decode_jwt_claims(access_token)
    id_claims = _decode_jwt_claims(id_token) if id_token else None
    identity["user_id"] = _claim_string(access_claims, "sub") or _claim_string(id_claims, "sub")
    identity["email"] = _claim_string(id_claims, "email") or _claim_string(access_claims, "email")
    identity["team_id"] = _claim_string(access_claims, "team_id") or _claim_string(id_claims, "team_id")

    if opts.get("skip_init_user"):
        # Still classify bot flag from JWT even if enrichment skipped.
        bot_class, bot_raw = _classify_convert_bot(access_claims)
        return identity, {"class": bot_class, "raw": bot_raw}

    enrich = {"agent_id": agent_id, "include_shell_identifier": True}

    # 05a: GET /v1/user — base auth headers (no enrichment fields yet).
    r = s.get(USER_URL, headers=cli_api_headers(access_token, cli_ver), timeout=15)
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

    # 05b: settings (enrichment headers with user_id/email/agent/shell).
    r = s.get(SETTINGS_URL, headers=cli_enrichment_headers(access_token, cli_ver, enrich),
              timeout=15)
    phases.append(trace("05b-settings", "GET", r))

    # 05c: models.
    r = s.get(MODELS_URL, headers=cli_enrichment_headers(access_token, cli_ver, enrich),
              timeout=15)
    phases.append(trace("05c-models", "GET", r))

    # 05d: bundle/archive.
    r = s.get(BUNDLE_URL, headers=cli_enrichment_headers(access_token, cli_ver, enrich),
              timeout=15)
    phases.append(trace("05d-bundle", "GET", r))

    # 05e: billing.
    r = s.get(BILLING_URL, headers=cli_enrichment_headers(access_token, cli_ver, enrich),
              timeout=15)
    phases.append(trace("05e-billing", "GET", r))

    # 05g: subscription — Go uses EnrichmentOptions{AgentID: f.agentID}
    # (only agent_id, no user_id/email/shell-identifier). Mirrors
    # sso_build.go:378 exactly.
    r = s.get(SUBSCRIPTION_URL,
              headers=cli_enrichment_headers(access_token, cli_ver, {"agent_id": agent_id}),
              timeout=15)
    phases.append(trace("05g-subscription", "GET", r))
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
        if em:
            identity["email"] = em
        if tid:
            identity["team_id"] = tid

    # Bot flag from access_token JWT (Go ClassifyConvertBot).
    bot_class, bot_raw = _classify_convert_bot(access_claims)
    bot_flag = {"class": bot_class, "raw": bot_raw}
    return identity, bot_flag


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
