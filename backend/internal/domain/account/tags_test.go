package account

import "testing"

func TestAccountTagHelpers(t *testing.T) {
	var empty Credential
	if empty.HasAccountTag(TagNoImage) {
		t.Fatal("empty should not have tag")
	}
	with := empty.WithAccountTag(TagNoImage).WithAccountTag(" NO_IMAGE ")
	if !with.HasAccountTag(TagNoImage) || len(with.Tags) != 1 {
		t.Fatalf("tags = %#v", with.Tags)
	}
	if !with.HasAnyAccountTag([]string{"other", TagNoImage}) {
		t.Fatal("expected any match")
	}
	cleared := with.WithoutAccountTag(TagNoImage)
	if cleared.HasAccountTag(TagNoImage) || len(cleared.Tags) != 0 {
		t.Fatalf("cleared = %#v", cleared.Tags)
	}
}
