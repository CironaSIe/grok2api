package account

import (
	"testing"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
)

func TestApplyCLIViewFiltersByLayer(t *testing.T) {
	trueVal := true
	views := []View{
		{CLILayer: 4, CLIProfile: &accountdomain.CLIProfile{}},
		{CLILayer: 5, CLIProfile: &accountdomain.CLIProfile{MaybeDead: true}},
		{CLILayer: 3, CLIProfile: &accountdomain.CLIProfile{TrustedSource: true}},
		{CLILayer: 4, CLIProfile: &accountdomain.CLIProfile{TrustedSource: true}}, // inconsistent layer vs tag; filter by layer SSOT
	}
	got := applyCLIViewFilters(views, ListFilter{CLILayer: 4})
	if len(got) != 2 {
		t.Fatalf("L4 filter len=%d want 2", len(got))
	}
	for _, v := range got {
		if v.CLILayer != 4 {
			t.Fatalf("unexpected layer %d", v.CLILayer)
		}
	}
	got = applyCLIViewFilters(views, ListFilter{CLILayer: 5})
	if len(got) != 1 || got[0].CLILayer != 5 {
		t.Fatalf("L5 filter = %#v", got)
	}
	got = applyCLIViewFilters(views, ListFilter{CLITrusted: &trueVal})
	if len(got) != 2 {
		t.Fatalf("trusted filter len=%d", len(got))
	}
}
