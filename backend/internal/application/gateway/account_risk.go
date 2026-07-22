package gateway

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/chenyme/grok2api/backend/internal/infra/provider"
)

// isAccountRiskImageError reports image generation failures with systemErrCode=1010
// (account/risk variance). These are switchable and must not drive long cooldowns.
func isAccountRiskImageError(err error) bool {
	if err == nil || provider.IsMediaPostProcessingError(err) {
		return false
	}
	return isAccountRiskSystemErr(imageSystemErrCodeFromText(err.Error()))
}

func isAccountRiskImageResponse(statusCode int, body []byte) bool {
	if statusCode >= 200 && statusCode < 300 {
		return false
	}
	if code := imageSystemErrCodeFromBody(body); isAccountRiskSystemErr(code) {
		return true
	}
	return isAccountRiskSystemErr(imageSystemErrCodeFromText(string(body)))
}

func isAccountRiskSystemErr(code any) bool {
	switch v := code.(type) {
	case nil:
		return false
	case int:
		return v == 1010
	case int64:
		return v == 1010
	case float64:
		return int(v) == 1010
	case string:
		v = strings.TrimSpace(v)
		if v == "" {
			return false
		}
		if n, err := strconv.Atoi(v); err == nil {
			return n == 1010
		}
		return strings.EqualFold(v, "1010")
	default:
		return false
	}
}

func imageSystemErrCodeFromBody(body []byte) any {
	bodyText := strings.TrimSpace(string(body))
	if bodyText == "" {
		return nil
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(bodyText), &data); err != nil {
		return imageSystemErrCodeFromText(bodyText)
	}
	if raw, ok := data["systemErrCode"]; ok {
		return normalizeSystemErrCode(raw)
	}
	if errObj, ok := data["error"].(map[string]any); ok {
		if raw, ok := errObj["systemErrCode"]; ok {
			return normalizeSystemErrCode(raw)
		}
	}
	return nil
}

func imageSystemErrCodeFromText(text string) any {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	lower := strings.ToLower(text)
	const marker = "systemerrcode="
	idx := strings.Index(lower, marker)
	if idx < 0 {
		if strings.Contains(lower, `"systemerrcode":1010`) || strings.Contains(lower, `"systemerrcode": 1010`) {
			return 1010
		}
		return nil
	}
	token := text[idx+len(marker):]
	token = strings.SplitN(token, "(", 2)[0]
	token = strings.SplitN(token, ",", 2)[0]
	token = strings.SplitN(token, " ", 2)[0]
	token = strings.Trim(token, `"'}`)
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	if n, err := strconv.Atoi(token); err == nil {
		return n
	}
	return token
}

func normalizeSystemErrCode(raw any) any {
	switch v := raw.(type) {
	case nil:
		return nil
	case bool:
		if v {
			return 1
		}
		return 0
	case float64:
		return int(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int(n)
		}
		return v.String()
	case string:
		v = strings.TrimSpace(v)
		if v == "" {
			return nil
		}
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		return v
	case int:
		return v
	case int64:
		return int(v)
	default:
		return nil
	}
}
