package account

import "strings"

// TagNoImage marks an account that failed image generation with account-risk
// systemErrCode (typically 1010). Media selection excludes it; chat does not.
const TagNoImage = "no_image"

// TagCLITrusted marks Web (or other) accounts imported as trusted supply for
// CLI layering. On Convert-to-Build it is inherited into build_cli_profiles.trusted_source.
// It is not proven success and does not raise layer above L3 by itself.
const TagCLITrusted = "cli_trusted"

// NormalizeAccountTag returns a canonical non-empty tag or empty if invalid.
func NormalizeAccountTag(tag string) string {
	return strings.ToLower(strings.TrimSpace(tag))
}

// HasAccountTag reports whether credential carries the tag.
func (c Credential) HasAccountTag(tag string) bool {
	tag = NormalizeAccountTag(tag)
	if tag == "" {
		return false
	}
	for _, item := range c.Tags {
		if NormalizeAccountTag(item) == tag {
			return true
		}
	}
	return false
}

// HasAnyAccountTag reports whether credential carries any of the tags.
func (c Credential) HasAnyAccountTag(tags []string) bool {
	for _, tag := range tags {
		if c.HasAccountTag(tag) {
			return true
		}
	}
	return false
}

// WithAccountTag returns a copy with tag added (idempotent).
func (c Credential) WithAccountTag(tag string) Credential {
	tag = NormalizeAccountTag(tag)
	if tag == "" || c.HasAccountTag(tag) {
		return c
	}
	next := append([]string(nil), c.Tags...)
	next = append(next, tag)
	c.Tags = next
	return c
}

// WithoutAccountTag returns a copy with tag removed.
func (c Credential) WithoutAccountTag(tag string) Credential {
	tag = NormalizeAccountTag(tag)
	if tag == "" || len(c.Tags) == 0 {
		return c
	}
	next := make([]string, 0, len(c.Tags))
	for _, item := range c.Tags {
		if NormalizeAccountTag(item) != tag {
			next = append(next, item)
		}
	}
	c.Tags = next
	return c
}
