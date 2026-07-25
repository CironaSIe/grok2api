package jsonshape

import (
	"strings"
	"testing"
)

func TestPreviewObjectKeysOnly(t *testing.T) {
	got := Preview([]byte(`{"error":{"code":"x","message":"secret-token"},"id":1}`))
	if got == "" || strings.Contains(got, "secret") || strings.Contains(got, "token") {
		t.Fatalf("preview leaked values: %q", got)
	}
	if !strings.Contains(got, "error") || !strings.Contains(got, "code") {
		t.Fatalf("preview missing keys: %q", got)
	}
}

func TestPreviewNonJSON(t *testing.T) {
	got := Preview([]byte("not-json-body"))
	if got != "non_json:13b" {
		t.Fatalf("got %q", got)
	}
}

func TestPreviewEmpty(t *testing.T) {
	if Preview(nil) != "empty" {
		t.Fatal(Preview(nil))
	}
}
