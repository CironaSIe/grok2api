// Package chattimeout plans non-stream chat wall-clock deadlines from payload size and model hints.
// Streaming requests keep provider idle/fixed semantics and must not use this total as a wall clock.
package chattimeout

import (
	"encoding/json"
	"strings"
	"time"
)

// Options controls dynamic non-stream chat timeouts.
// Max should be aligned to the provider's configured chatTimeout ceiling.
type Options struct {
	Dynamic               bool
	Base                  time.Duration
	Min                   time.Duration
	Max                   time.Duration
	Per1kPrompt           time.Duration
	Per1kOutput           time.Duration
	ReasoningBonus        time.Duration
	ReasoningPromptFactor float64
	DefaultOutputTokens   int
	Connect               time.Duration
}

// DefaultOptions matches the free-pool ops formula used by the Python pool:
// total ≈ base(60s) + 5s * (est_in/1000), clamped to [min, max].
func DefaultOptions() Options {
	return Options{
		Dynamic:               true,
		Base:                  60 * time.Second,
		Min:                   60 * time.Second,
		Max:                   5 * time.Minute,
		Per1kPrompt:           5 * time.Second,
		Per1kOutput:           0,
		ReasoningBonus:        0,
		ReasoningPromptFactor: 1.0,
		DefaultOutputTokens:   4096,
		Connect:               30 * time.Second,
	}
}

// Input is one chat/responses attempt's planning inputs.
type Input struct {
	Streaming       bool
	Model           string
	Payload         []byte
	PayloadBytes    int
	EstPromptTokens int
	MaxOutputTokens int
	Options         Options
}

// Plan is the resolved timeout for one non-stream attempt.
// Stream=true and Total=0 mean "do not wrap ctx with a dynamic total".
type Plan struct {
	Total           time.Duration
	Connect         time.Duration
	EstPromptTokens int
	PayloadBytes    int
	Dynamic         bool
	Stream          bool
	Reasoning       bool
}

// PlanChat computes connect/total timeouts. Streaming always returns Total=0 (no dynamic wall clock).
func PlanChat(in Input) Plan {
	opts := normalizeOptions(in.Options)
	payloadBytes := in.PayloadBytes
	if payloadBytes <= 0 && len(in.Payload) > 0 {
		payloadBytes = len(in.Payload)
	}
	estIn := in.EstPromptTokens
	if estIn <= 0 {
		estIn = EstimatePromptTokensFromBytes(payloadBytes)
	}
	reasoning := IsReasoningModel(in.Model)
	outBudget := in.MaxOutputTokens
	if outBudget <= 0 {
		if extracted := ExtractMaxOutputTokens(in.Payload); extracted > 0 {
			outBudget = extracted
		} else {
			outBudget = opts.DefaultOutputTokens
		}
	}

	plan := Plan{
		EstPromptTokens: estIn,
		PayloadBytes:    payloadBytes,
		Stream:          in.Streaming,
		Reasoning:       reasoning,
		Dynamic:         opts.Dynamic && !in.Streaming,
	}
	if in.Streaming {
		// Streaming keeps provider fixed/idle timeouts; never apply a total wall clock here.
		plan.Connect = minDuration(opts.Connect, opts.Max)
		return plan
	}

	total := opts.Max
	if opts.Dynamic {
		promptRate := opts.Per1kPrompt
		if reasoning && opts.ReasoningPromptFactor > 0 {
			promptRate = time.Duration(float64(promptRate) * opts.ReasoningPromptFactor)
		}
		raw := opts.Base +
			time.Duration(estIn)*promptRate/1000 +
			time.Duration(outBudget)*opts.Per1kOutput/1000 +
			opts.ReasoningBonus
		if raw < opts.Base {
			raw = opts.Base
		}
		total = raw
		if total < opts.Min {
			total = opts.Min
		}
		if total > opts.Max {
			total = opts.Max
		}
	} else {
		total = opts.Max
		if total < opts.Min {
			total = opts.Min
		}
	}
	if total <= 0 {
		total = opts.Min
	}
	connect := opts.Connect
	if connect <= 0 {
		connect = 30 * time.Second
	}
	if connect > total {
		connect = total
	}
	plan.Total = total
	plan.Connect = connect
	return plan
}

// EstimatePromptTokensFromBytes uses a light ~4 bytes/token heuristic.
func EstimatePromptTokensFromBytes(n int) int {
	if n <= 0 {
		return 0
	}
	return (n + 3) / 4
}

// IsReasoningModel detects models that typically need longer non-stream budgets.
func IsReasoningModel(model string) bool {
	name := strings.ToLower(strings.TrimSpace(model))
	if name == "" {
		return false
	}
	if strings.Contains(name, "reasoning") {
		return true
	}
	if strings.HasSuffix(name, "-thinking") {
		return true
	}
	if strings.Contains(name, "think") && strings.Contains(name, "console") {
		return true
	}
	return false
}

// ExtractMaxOutputTokens peeks max_tokens / max_output_tokens from a JSON body.
func ExtractMaxOutputTokens(body []byte) int {
	body = bytesTrimSpace(body)
	if len(body) == 0 || body[0] != '{' {
		return 0
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return 0
	}
	for _, key := range []string{"max_tokens", "max_output_tokens", "max_completion_tokens"} {
		item, ok := raw[key]
		if !ok {
			continue
		}
		var n int
		if err := json.Unmarshal(item, &n); err == nil && n > 0 {
			return n
		}
		var f float64
		if err := json.Unmarshal(item, &f); err == nil && f > 0 {
			return int(f)
		}
	}
	return 0
}

func normalizeOptions(opts Options) Options {
	def := DefaultOptions()
	if opts.Base <= 0 {
		opts.Base = def.Base
	}
	if opts.Min <= 0 {
		opts.Min = def.Min
	}
	if opts.Max <= 0 {
		opts.Max = def.Max
	}
	if opts.Max < opts.Min {
		opts.Min = opts.Max
	}
	if opts.Per1kPrompt < 0 {
		opts.Per1kPrompt = 0
	}
	if opts.Per1kOutput < 0 {
		opts.Per1kOutput = 0
	}
	if opts.ReasoningBonus < 0 {
		opts.ReasoningBonus = 0
	}
	if opts.ReasoningPromptFactor <= 0 {
		opts.ReasoningPromptFactor = def.ReasoningPromptFactor
	}
	if opts.DefaultOutputTokens <= 0 {
		opts.DefaultOutputTokens = def.DefaultOutputTokens
	}
	if opts.Connect <= 0 {
		opts.Connect = def.Connect
	}
	// Dynamic defaults to true when zero-value Options is used with Dynamic=false explicitly...
	// Callers should set Dynamic intentionally; DefaultOptions sets true.
	return opts
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 || a < b {
		return a
	}
	return b
}

func bytesTrimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}
