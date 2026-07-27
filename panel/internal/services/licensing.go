package services

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

const licenseSecretEnvKey = "LICENSE_SECRET"

var licenseSecret string

func init() {
	licenseSecret = os.Getenv(licenseSecretEnvKey)
	if licenseSecret == "" {
		slog.Warn("LICENSE_SECRET not set — generating ephemeral key. All existing licenses will become invalid on restart. Set LICENSE_SECRET to a persistent random string to prevent data loss.")
		b := make([]byte, 32)
		rand.Read(b)
		licenseSecret = fmt.Sprintf("%x", b)
	}
}

func getLicenseSecret() string {
	return licenseSecret
}

func GenerateLicenseKey(tier string, duration time.Duration) (string, time.Time) {
	expiresAt := time.Now().Add(duration)

	tierBytes := []byte(tier)
	payload := make([]byte, len(tierBytes)+8+8)
	copy(payload, tierBytes)
	binary.BigEndian.PutUint64(payload[len(tierBytes):], uint64(expiresAt.Unix()))
	rand.Read(payload[len(tierBytes)+8:])

	mac := hmac.New(sha256.New, []byte(getLicenseSecret()))
	mac.Write(payload)
	sig := mac.Sum(nil)[:4]

	full := append(payload, sig...)

	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(full)

	var groups string
	for i := 0; i < len(encoded); i += 5 {
		end := i + 5
		if end > len(encoded) {
			end = len(encoded)
		}
		if groups != "" {
			groups += "-"
		}
		groups += encoded[i:end]
	}

	return fmt.Sprintf("MIRAGE-%s-%s", tier, groups), expiresAt
}

func VerifyLicenseKey(key string) (string, time.Time, bool) {
	if !strings.HasPrefix(key, "MIRAGE-") {
		return "", time.Time{}, false
	}

	parts := strings.SplitN(key, "-", 3)
	if len(parts) < 3 || parts[1] == "" || parts[2] == "" {
		return "", time.Time{}, false
	}

	tier := parts[1]
	encoded := strings.ReplaceAll(parts[2], "-", "")

	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil || len(raw) < 5 {
		return "", time.Time{}, false
	}

	sig := raw[len(raw)-4:]
	payload := raw[:len(raw)-4]

	if len(payload) < 17 {
		return "", time.Time{}, false
	}

	expiryUnix := int64(binary.BigEndian.Uint64(payload[len(payload)-16:]))
	payloadTier := string(payload[:len(payload)-16])

	if payloadTier != tier {
		return "", time.Time{}, false
	}

	mac := hmac.New(sha256.New, []byte(getLicenseSecret()))
	mac.Write(payload)
	expectedSig := mac.Sum(nil)[:4]

	if !hmac.Equal(sig, expectedSig) {
		return "", time.Time{}, false
	}

	expiresAt := time.Unix(expiryUnix, 0)
	if time.Now().After(expiresAt) {
		return tier, expiresAt, false
	}

	return tier, expiresAt, true
}
