package sso2oauth

import "encoding/json"

// ConvertRequest is the request body sent from Go to the Python daemon
// via POST /convert. See 修改计划.md §16.4 for the contract.
type ConvertRequest struct {
	SsoToken   string         `json:"sso_token"`
	ProxyURL   string         `json:"proxy_url"`
	UserAgent  string         `json:"user_agent"`
	CFCookies  string         `json:"cf_cookies"`
	CLIVersion string         `json:"cli_version"`
	Options    ConvertOptions `json:"options"`
}

// ConvertOptions carries tunable conversion flags. All default to false
// on the Python side when not set.
type ConvertOptions struct {
	SoftPreflight bool `json:"soft_preflight"`
	SkipInitUser  bool `json:"skip_init_user"`
	SkipBotReject bool `json:"skip_bot_reject"`
}

// ConvertResponse is the daemon reply. On success OK=true with Tokens,
// Identity, BotFlag, Enrichment and Phases populated. On failure OK=false
// with Error* fields and Phases containing the trace up to the failing phase.
type ConvertResponse struct {
	OK           bool           `json:"ok"`
	Tokens       *TokenSet      `json:"tokens,omitempty"`
	Identity     *Identity      `json:"identity,omitempty"`
	BotFlag      *BotFlag       `json:"bot_flag,omitempty"`
	Enrichment   *EnrichmentData `json:"enrichment,omitempty"`
	Phases       []PhaseTrace   `json:"phases,omitempty"`
	ErrorPhase   string         `json:"error_phase,omitempty"`
	ErrorStatus  int            `json:"error_status,omitempty"`
	ErrorMessage string         `json:"error_message,omitempty"`
	ErrorURL     string         `json:"error_url,omitempty"`
}

// EnrichmentData carries enrichment-phase data that Go can reuse to
// avoid redundant API calls after conversion. Models is a list of
// upstream model IDs. BillingRaw and SubscriptionRaw are the raw JSON
// response bodies from /v1/billing?format=credits and
// /v1/user?include=subscription, parsed by Go's cli.ParseBilling and
// cli.ParseSubscriptionTier. RateLimits carries grok.com rate-limit
// info from Phase 00a.
type EnrichmentData struct {
	Models          []string       `json:"models,omitempty"`
	BillingRaw      json.RawMessage `json:"billing_raw,omitempty"`
	SubscriptionRaw json.RawMessage `json:"subscription_raw,omitempty"`
	RateLimits      *RateLimits    `json:"rate_limits,omitempty"`
}

// RateLimits carries the grok.com rate-limits snapshot from Phase 00a.
type RateLimits struct {
	RemainingQueries int `json:"remaining_queries"`
	TotalQueries     int `json:"total_queries"`
	WindowSeconds    int `json:"window_seconds"`
}

// TokenSet mirrors the OAuth2 token response from xAI's token endpoint.
type TokenSet struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
}

// Identity is derived from the id_token claims and the init_user response.
type Identity struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	TeamID string `json:"team_id"`
}

// BotFlag carries the bot classification. Class is one of
// "clean" | "contaminated" | "super_signal"; Raw is the original
// bot_flag_source string from xAI.
type BotFlag struct {
	Class string `json:"class"`
	Raw   string `json:"raw"`
}

// PhaseTrace records one HTTP exchange in the 9-step flow. The daemon
// redacts request.Cookie to "[redacted]" and truncates response bodies
// to 512 characters in BodyPreview.
type PhaseTrace struct {
	Name     string        `json:"name"`
	Request  PhaseRequest  `json:"request"`
	Response PhaseResponse `json:"response"`
}

// PhaseRequest is the redacted request snapshot. Body is nil when the
// request had no body.
type PhaseRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    *string           `json:"body"`
}

// PhaseResponse is the response snapshot. Headers retains Set-Cookie so
// Go can observe which CF cookies were issued.
type PhaseResponse struct {
	Status      int               `json:"status"`
	Headers     map[string]string `json:"headers"`
	BodyPreview string            `json:"body_preview"`
}
