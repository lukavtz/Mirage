package services_test

import (
	"testing"
	"time"

	"github.com/user/mirage-panel/internal/services"
)

func TestLicense_GenerateAndVerify(t *testing.T) {
	tier := "starter"
	duration := 30 * 24 * time.Hour

	key, expiresAt := services.GenerateLicenseKey(tier, duration)

	if key == "" {
		t.Fatal("expected non-empty license key")
	}

	if expiresAt.IsZero() {
		t.Fatal("expected non-zero expiry")
	}

	if time.Until(expiresAt) < duration-time.Minute {
		t.Errorf("expiry too soon: %v", time.Until(expiresAt))
	}

	verifiedTier, verifiedExpiry, valid := services.VerifyLicenseKey(key)
	if !valid {
		t.Fatal("expected valid license key")
	}

	if verifiedTier != tier {
		t.Errorf("expected tier %q, got %q", tier, verifiedTier)
	}

	if verifiedExpiry.Unix() != expiresAt.Unix() {
		t.Errorf("expected expiry %v, got %v", expiresAt, verifiedExpiry)
	}
}

func TestLicense_InvalidSignature(t *testing.T) {
	tier := "pro"
	duration := 365 * 24 * time.Hour

	key, _ := services.GenerateLicenseKey(tier, duration)

	// Replace a middle character to corrupt the HMAC signature
	runes := []rune(key)
	for i := len(runes) / 2; i < len(runes); i++ {
		if runes[i] != '-' {
			runes[i] = 'Z'
			break
		}
	}
	tampered := string(runes)

	if tampered == key {
		t.Fatal("tampered key should differ from original")
	}

	_, _, valid := services.VerifyLicenseKey(tampered)
	if valid {
		t.Error("expected invalid for tampered key")
	}
}

func TestLicense_Expired(t *testing.T) {
	tier := "enterprise"
	duration := -1 * time.Hour

	key, _ := services.GenerateLicenseKey(tier, duration)

	_, _, valid := services.VerifyLicenseKey(key)
	if valid {
		t.Error("expected invalid for expired key")
	}
}

func TestLicense_TierParsing(t *testing.T) {
	tiers := []struct {
		name string
		tier string
	}{
		{"starter", "starter"},
		{"pro", "pro"},
		{"enterprise", "enterprise"},
		{"custom", "custom"},
	}

	for _, tt := range tiers {
		t.Run(tt.name, func(t *testing.T) {
			key, _ := services.GenerateLicenseKey(tt.tier, 24*time.Hour)

			verifiedTier, _, valid := services.VerifyLicenseKey(key)
			if !valid {
				t.Fatalf("expected valid key for tier %q", tt.tier)
			}

			if verifiedTier != tt.tier {
				t.Errorf("expected tier %q, got %q", tt.tier, verifiedTier)
			}
		})
	}
}

func TestLicense_InvalidFormat(t *testing.T) {
	tests := []string{
		"",
		"INVALID",
		"MIRAGE-starter",
		"MIRAGE-starter-",
		"NOTMIRAGE-starter-AAAA",
	}

	for _, key := range tests {
		_, _, valid := services.VerifyLicenseKey(key)
		if valid {
			t.Errorf("expected invalid for key %q", key)
		}
	}
}
