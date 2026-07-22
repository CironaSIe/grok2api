package xaiauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// DecodeClaims base64url-decodes a JWT payload without signature verification.
func DecodeClaims(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some tokens may include standard padding.
		padded := parts[1] + strings.Repeat("=", (4-len(parts[1])%4)%4)
		data, err = base64.URLEncoding.DecodeString(padded)
		if err != nil {
			return nil
		}
	}
	var claims map[string]any
	if json.Unmarshal(data, &claims) != nil {
		return nil
	}
	return claims
}

// ClaimString returns a string claim, stringifying numbers when needed.
func ClaimString(claims map[string]any, key string) string {
	if claims == nil {
		return ""
	}
	value, ok := claims[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strings.TrimSpace(strconv.FormatFloat(typed, 'f', -1, 64))
	case json.Number:
		return strings.TrimSpace(typed.String())
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

// IdentityFromTokens maps access/id JWT claims into account identity fields.
// Prefer access for sub/team/bot; id_token email first, then access email.
func IdentityFromTokens(accessToken, idToken string) (userID, email, teamID string, accessClaims map[string]any) {
	accessClaims = DecodeClaims(accessToken)
	idClaims := DecodeClaims(idToken)
	userID = ClaimString(accessClaims, "sub")
	if userID == "" {
		userID = ClaimString(idClaims, "sub")
	}
	email = ClaimString(idClaims, "email")
	if email == "" {
		email = ClaimString(accessClaims, "email")
	}
	teamID = ClaimString(accessClaims, "team_id")
	if teamID == "" {
		teamID = ClaimString(idClaims, "team_id")
	}
	return userID, email, teamID, accessClaims
}

// ConvertBotClass classifies access_token bot_flag_source for Convert pool gate.
// clean: claim absent or string "NP" (case-insensitive) or empty.
// contaminated: any other present string/non-zero marker (sso2oauth semantics).
// superSignal: JSON number 1 — runtime Super/XAI routing only; NOT convert rejection.
type ConvertBotClass string

const (
	ConvertBotClean        ConvertBotClass = "clean"
	ConvertBotContaminated ConvertBotClass = "contaminated"
	ConvertBotSuperSignal  ConvertBotClass = "super_signal"
)

// ClassifyConvertBot inspects access JWT bot_flag_source.
// super_signal (numeric 1) is reported separately and is not convert contamination.
func ClassifyConvertBot(accessClaims map[string]any) (ConvertBotClass, string) {
	if accessClaims == nil {
		return ConvertBotClean, ""
	}
	raw, ok := accessClaims["bot_flag_source"]
	if !ok || raw == nil {
		return ConvertBotClean, ""
	}
	switch typed := raw.(type) {
	case float64:
		if typed == 1 {
			return ConvertBotSuperSignal, "1"
		}
		if typed == 0 {
			return ConvertBotClean, "0"
		}
		return ConvertBotContaminated, formatBotRaw(raw)
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" || strings.EqualFold(trimmed, "NP") {
			return ConvertBotClean, trimmed
		}
		if trimmed == "1" {
			// Ambiguous string "1": treat as super signal for convert gate (allow), runtime still parses numeric.
			return ConvertBotSuperSignal, trimmed
		}
		return ConvertBotContaminated, trimmed
	default:
		s := formatBotRaw(raw)
		if s == "" || strings.EqualFold(s, "NP") {
			return ConvertBotClean, s
		}
		return ConvertBotContaminated, s
	}
}

func formatBotRaw(raw any) string {
	switch typed := raw.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return strings.TrimSpace(fmt.Sprint(raw))
	}
}
