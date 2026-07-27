// Package jsonshape builds truncated JSON key trees for failure diagnostics.
// It never logs values or full bodies — only structure, depth- and width-limited.
package jsonshape

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	DefaultMaxDepth  = 4
	DefaultMaxWidth  = 12
	DefaultMaxRunes  = 240
	nonJSONMarker    = "non_json"
	truncatedMarker  = "…"
)

// Preview returns a compact structural preview of data suitable for Warn logs.
// On invalid JSON it reports non_json with a short length hint, never the body.
func Preview(data []byte) string {
	return PreviewLimits(data, DefaultMaxDepth, DefaultMaxWidth, DefaultMaxRunes)
}

// PreviewLimits is Preview with explicit tree limits.
func PreviewLimits(data []byte, maxDepth, maxWidth, maxRunes int) string {
	if maxDepth < 1 {
		maxDepth = DefaultMaxDepth
	}
	if maxWidth < 1 {
		maxWidth = DefaultMaxWidth
	}
	if maxRunes < 16 {
		maxRunes = DefaultMaxRunes
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return "empty"
	}
	var root any
	if err := json.Unmarshal([]byte(trimmed), &root); err != nil {
		return nonJSONMarker + ":" + sizeHint(len(data))
	}
	tree := keyTree(root, 0, maxDepth, maxWidth)
	if tree == "" {
		return "scalar"
	}
	return truncateRunes(tree, maxRunes)
}

func keyTree(value any, depth, maxDepth, maxWidth int) string {
	if depth >= maxDepth {
		return truncatedMarker
	}
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) == 0 {
			return "{}"
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, min(len(keys), maxWidth))
		limit := len(keys)
		if limit > maxWidth {
			limit = maxWidth
		}
		for i := 0; i < limit; i++ {
			key := keys[i]
			child := keyTree(typed[key], depth+1, maxDepth, maxWidth)
			if child == "" || child == "scalar" {
				parts = append(parts, key)
				continue
			}
			parts = append(parts, key+":"+child)
		}
		if len(keys) > maxWidth {
			parts = append(parts, truncatedMarker)
		}
		return "{" + strings.Join(parts, ",") + "}"
	case []any:
		if len(typed) == 0 {
			return "[]"
		}
		// Arrays only expose element shape of the first item (width-safe).
		child := keyTree(typed[0], depth+1, maxDepth, maxWidth)
		if child == "" || child == "scalar" {
			return "[]"
		}
		return "[" + child + "]"
	default:
		return "scalar"
	}
}

func sizeHint(n int) string {
	switch {
	case n <= 0:
		return "0b"
	case n < 1024:
		return itoa(n) + "b"
	default:
		return itoa(n/1024) + "kb"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func truncateRunes(value string, maxRunes int) string {
	if utf8.RuneCountInString(value) <= maxRunes {
		return value
	}
	runes := []rune(value)
	if maxRunes < 1 {
		return truncatedMarker
	}
	return string(runes[:maxRunes-1]) + truncatedMarker
}
