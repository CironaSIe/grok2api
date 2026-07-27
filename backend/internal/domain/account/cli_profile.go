package account

import "time"

// CLIProfile is Build-only operational state for CLI layering and warm pool.
// Eligibility and layer are derived at use time; they are not stored as enums.
type CLIProfile struct {
	AccountID        uint64
	LastSuccessAt    *time.Time
	SuccessCount     int
	CallCount        int
	TrustedSource    bool
	MaybeDead        bool
	Consecutive403   int
	NextEligibleAt   *time.Time
	TokenGeneration  int
	LastCLIErrorCode string
	// LastExploreAt is when warm-side unproven explore last ran (nil = never).
	LastExploreAt *time.Time
	UpdatedAt     time.Time
}

// IsProven reports whether this Build account has a recorded CLI success.
func (p CLIProfile) IsProven() bool {
	return p.LastSuccessAt != nil && !p.LastSuccessAt.IsZero()
}

// ProfileOrEmpty returns the candidate profile or a zero value.
func (c RoutingCandidate) ProfileOrEmpty() CLIProfile {
	if c.CLIProfile == nil {
		return CLIProfile{AccountID: c.Credential.ID}
	}
	out := *c.CLIProfile
	if out.AccountID == 0 {
		out.AccountID = c.Credential.ID
	}
	return out
}
