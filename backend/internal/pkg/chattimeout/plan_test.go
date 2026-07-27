package chattimeout

import (
	"strings"
	"testing"
	"time"
)

func TestPlanChatStreamingNoWallClock(t *testing.T) {
	plan := PlanChat(Input{
		Streaming: true,
		Model:     "grok-3",
		Payload:   []byte(`{"messages":[{"role":"user","content":"` + strings.Repeat("x", 8000) + `"}]}`),
		Options:   DefaultOptions(),
	})
	if !plan.Stream || plan.Total != 0 {
		t.Fatalf("stream plan = %#v", plan)
	}
}

func TestPlanChatShortNearMin(t *testing.T) {
	opts := DefaultOptions()
	opts.Max = 5 * time.Minute
	plan := PlanChat(Input{
		Streaming: false,
		Model:     "grok-3",
		Payload:   []byte(`{"messages":[{"role":"user","content":"hi"}]}`),
		Options:   opts,
	})
	if plan.Total < opts.Min || plan.Total > opts.Max {
		t.Fatalf("total=%s not in [%s,%s]", plan.Total, opts.Min, opts.Max)
	}
	// short prompt should stay near min when formula is base+small
	if plan.Total < opts.Min || plan.Total > opts.Min+time.Second {
		t.Fatalf("short total=%s want near min=%s", plan.Total, opts.Min)
	}
}

func TestPlanChatLongPromptGrowsAndClamps(t *testing.T) {
	opts := DefaultOptions()
	opts.Max = 3 * time.Minute
	opts.Min = 60 * time.Second
	opts.Base = 60 * time.Second
	opts.Per1kPrompt = 5 * time.Second
	// ~40k tokens -> +200s => would be 260s but clamp to 180s
	plan := PlanChat(Input{
		Streaming:       false,
		Model:           "grok-3",
		EstPromptTokens: 40000,
		MaxOutputTokens: 16,
		Options:         opts,
	})
	if plan.Total != opts.Max {
		t.Fatalf("long total=%s want max=%s", plan.Total, opts.Max)
	}
	small := PlanChat(Input{
		Streaming:       false,
		Model:           "grok-3",
		EstPromptTokens: 100,
		MaxOutputTokens: 16,
		Options:         opts,
	})
	if plan.Total < small.Total {
		t.Fatalf("long %s < small %s", plan.Total, small.Total)
	}
}

func TestPlanChatStaticWhenDynamicOff(t *testing.T) {
	opts := DefaultOptions()
	opts.Dynamic = false
	opts.Max = 200 * time.Second
	opts.Min = 60 * time.Second
	plan := PlanChat(Input{
		Streaming:       false,
		Model:           "grok-4-reasoning-console",
		EstPromptTokens: 100000,
		Options:         opts,
	})
	if plan.Dynamic {
		t.Fatal("expected static")
	}
	if plan.Total != opts.Max {
		t.Fatalf("total=%s want %s", plan.Total, opts.Max)
	}
}

func TestIsReasoningModelAndExtractMaxTokens(t *testing.T) {
	if !IsReasoningModel("grok-4.20-0309-reasoning-console") {
		t.Fatal("reasoning")
	}
	if IsReasoningModel("grok-3") {
		t.Fatal("non-reasoning")
	}
	if got := ExtractMaxOutputTokens([]byte(`{"max_tokens":8192}`)); got != 8192 {
		t.Fatalf("max_tokens=%d", got)
	}
	if got := ExtractMaxOutputTokens([]byte(`{"max_output_tokens":2048}`)); got != 2048 {
		t.Fatalf("max_output_tokens=%d", got)
	}
}
