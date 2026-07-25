package account

import (
	"strings"
	"time"
)

// CLILayer is the hard selection priority for Build/CLI (1 = best).
type CLILayer int

const (
	CLILayerNonFreeProven CLILayer = 1
	CLILayerProven        CLILayer = 2
	CLILayerTrusted       CLILayer = 3
	CLILayerUnproven      CLILayer = 4
	CLILayerBotUnproven   CLILayer = 5
)

// CLIEligibility is serviceability for Build/CLI (orthogonal to layer).
type CLIEligibility string

const (
	CLIEligibilityReady          CLIEligibility = "ready"
	CLIEligibilityRefreshable    CLIEligibility = "refreshable"
	CLIEligibilityAcquireAllowed CLIEligibility = "acquire_allowed"
	CLIEligibilityTempBlocked    CLIEligibility = "temp_blocked"
	CLIEligibilityDenied         CLIEligibility = "denied"
	// CLIEligibilityBotFlagged is a soft label (optional); soft bot normally keeps READY/REFRESHABLE
	// and only drops to layer 5 when unproven. Prefer layer over this enum for selection.
	CLIEligibilityBotFlagged CLIEligibility = "bot_flagged"
	// CLIEligibilityChatBanned is maybe_dead: hard reject (not the same as L5 soft bot).
	CLIEligibilityChatBanned CLIEligibility = "chat_banned"
)

// WarmBucket identifies warm-pool fill buckets (may split nonfree unproven from L1).
type WarmBucket string

const (
	WarmBucketL1              WarmBucket = "l1"
	WarmBucketL2              WarmBucket = "l2"
	WarmBucketNonFreeUnproven WarmBucket = "nonfree_unproven"
	WarmBucketL3              WarmBucket = "l3"
	WarmBucketL4              WarmBucket = "l4"
	WarmBucketL5              WarmBucket = "l5"
)

// DefaultCLIAccessSkew is the safety window before access expiry for READY.
const DefaultCLIAccessSkew = 60 * time.Second

// CLIClassifyInput feeds ClassifyCLI. Profile may be empty (unproven defaults).
type CLIClassifyInput struct {
	Credential Credential
	Billing    *Billing
	Profile    CLIProfile
	Now        time.Time
	AccessSkew time.Duration // <=0 uses DefaultCLIAccessSkew
	BotFlagged bool          // runtime JWT / convert soft bot (not Web reauth, not maybe_dead)
}

// CLIClassification is the pure-function result shared by selector and warm worker.
type CLIClassification struct {
	Layer             CLILayer
	Eligibility       CLIEligibility
	WarmBucket        WarmBucket
	Proven            bool
	NonFree           bool
	Selectable        bool // READY or REFRESHABLE (chat_banned never)
	AcquireSelectable bool // also allows ACQUIRE_ALLOWED (request-path optional)
	CountsTowardWarm  bool // READY and bucket allowed into warm total
	WarmFillAllowed   bool // bucket may receive warm fill (L5 default false)
}

// ClassifyCLI derives layer, eligibility, and warm bucket. No I/O.
// Non-Build credentials always return denied / layer 5 / no warm.
//
// maybe_dead (chat ban) is a hard veto: never selectable, never warm.
// Soft BotFlagged only affects layer when unproven (L5); token eligibility stays normal
// so L5 can still be used when higher layers are empty (aligned with ~/grok2api _cli_layer).
func ClassifyCLI(in CLIClassifyInput) CLIClassification {
	now := in.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	skew := in.AccessSkew
	if skew <= 0 {
		skew = DefaultCLIAccessSkew
	}

	out := CLIClassification{
		Layer:       CLILayerBotUnproven,
		Eligibility: CLIEligibilityDenied,
		WarmBucket:  WarmBucketL5,
	}
	if in.Credential.Provider != ProviderBuild {
		return out
	}

	profile := in.Profile
	if profile.AccountID == 0 {
		profile.AccountID = in.Credential.ID
	}
	nonFree := IsBuildSuper(in.Credential, in.Billing)
	proven := profile.IsProven()
	// Chat ban (maybe_dead): never selectable, never warm — regardless of residual proven.
	if profile.MaybeDead {
		out.NonFree = nonFree
		out.Proven = proven
		out.Layer = CLILayerBotUnproven
		out.WarmBucket = WarmBucketL5
		if !in.Credential.Enabled || in.Credential.AuthStatus == AuthStatusReauthRequired {
			out.Eligibility = CLIEligibilityDenied
		} else {
			out.Eligibility = CLIEligibilityChatBanned
		}
		out.Selectable = false
		out.AcquireSelectable = false
		out.WarmFillAllowed = false
		out.CountsTowardWarm = false
		return out
	}
	botish := in.BotFlagged
	out.NonFree = nonFree
	out.Proven = proven
	// Proven always wins layer (Python: has_success before bot check).
	out.Layer = classifyCLILayer(nonFree, proven, profile.TrustedSource, botish)
	out.WarmBucket = warmBucketFor(out.Layer, nonFree, proven)
	// Soft bot does not force a non-selectable eligibility; Access/RT decide serviceability.
	out.Eligibility = classifyCLIEligibility(in.Credential, profile, now, skew)
	out.Selectable = out.Eligibility == CLIEligibilityReady || out.Eligibility == CLIEligibilityRefreshable
	out.AcquireSelectable = out.Selectable || out.Eligibility == CLIEligibilityAcquireAllowed
	out.WarmFillAllowed = out.WarmBucket != WarmBucketL5 && out.WarmBucket != ""
	out.CountsTowardWarm = out.Eligibility == CLIEligibilityReady && out.WarmFillAllowed
	return out
}

func classifyCLILayer(nonFree, proven, trusted, botish bool) CLILayer {
	if proven {
		if nonFree {
			return CLILayerNonFreeProven
		}
		return CLILayerProven
	}
	if botish {
		return CLILayerBotUnproven
	}
	if trusted {
		return CLILayerTrusted
	}
	return CLILayerUnproven
}

func warmBucketFor(layer CLILayer, nonFree, proven bool) WarmBucket {
	if !proven && nonFree {
		return WarmBucketNonFreeUnproven
	}
	switch layer {
	case CLILayerNonFreeProven:
		return WarmBucketL1
	case CLILayerProven:
		return WarmBucketL2
	case CLILayerTrusted:
		return WarmBucketL3
	case CLILayerUnproven:
		return WarmBucketL4
	default:
		return WarmBucketL5
	}
}

func classifyCLIEligibility(cred Credential, profile CLIProfile, now time.Time, skew time.Duration) CLIEligibility {
	if !cred.Enabled || cred.AuthStatus == AuthStatusReauthRequired {
		return CLIEligibilityDenied
	}
	if profile.NextEligibleAt != nil && profile.NextEligibleAt.After(now) {
		return CLIEligibilityTempBlocked
	}
	if accessUsable(cred, now, skew) {
		return CLIEligibilityReady
	}
	if strings.TrimSpace(cred.EncryptedRefreshToken) != "" && !cred.RefreshPermanent {
		return CLIEligibilityRefreshable
	}
	if strings.TrimSpace(cred.EncryptedRefreshToken) != "" && cred.RefreshPermanent {
		// RT marked permanent-dead: only SSO convert can revive.
		return CLIEligibilityAcquireAllowed
	}
	if strings.TrimSpace(cred.EncryptedAccessToken) != "" {
		// Has ciphertext but expired / unknown exp with no RT.
		return CLIEligibilityAcquireAllowed
	}
	return CLIEligibilityAcquireAllowed
}

func accessUsable(cred Credential, now time.Time, skew time.Duration) bool {
	if strings.TrimSpace(cred.EncryptedAccessToken) == "" {
		return false
	}
	if cred.ExpiresAt.IsZero() {
		// Unknown expiry: treat as usable until refresh path says otherwise.
		return true
	}
	return cred.ExpiresAt.After(now.Add(skew))
}

// EligibilityRank orders serviceability for within-layer scoring (higher better).
func EligibilityRank(e CLIEligibility) int {
	switch e {
	case CLIEligibilityReady:
		return 5
	case CLIEligibilityRefreshable:
		return 4
	case CLIEligibilityAcquireAllowed:
		return 3
	case CLIEligibilityTempBlocked:
		return 2
	case CLIEligibilityBotFlagged:
		// Soft label only; if ever used as eligibility, still above hard rejects.
		return 1
	case CLIEligibilityChatBanned:
		return 0
	default:
		return 0
	}
}

// UnprovenWarmBucket reports whether a warm bucket counts against the unproven cap.
func UnprovenWarmBucket(b WarmBucket) bool {
	switch b {
	case WarmBucketL3, WarmBucketL4, WarmBucketNonFreeUnproven:
		return true
	default:
		return false
	}
}
