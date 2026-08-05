package auth_test

import (
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"zialfi-panel/internal/auth"
)

func TestNewTOTPManager(t *testing.T) {
	m := auth.NewTOTPManager()
	if m == nil {
		t.Fatal("expected non-nil TOTPManager")
	}
}

func TestGenerateSecret(t *testing.T) {
	m := auth.NewTOTPManager()
	secret, qrBase64, err := m.GenerateSecret("test-user", "TestApp")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}
	if secret == "" {
		t.Fatal("expected non-empty secret")
	}
	if qrBase64 == "" {
		t.Fatal("expected non-empty QR base64")
	}
}

func TestValidateValidCode(t *testing.T) {
	m := auth.NewTOTPManager()
	secret, _, err := m.GenerateSecret("test-user", "TestApp")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	if !m.Validate(code, secret) {
		t.Error("expected valid code to pass validation")
	}
}

func TestValidateWrongCode(t *testing.T) {
	m := auth.NewTOTPManager()
	secret, _, err := m.GenerateSecret("test-user", "TestApp")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	if m.Validate("000000", secret) {
		t.Error("expected wrong code to fail validation")
	}
}

func TestValidateEmptyCode(t *testing.T) {
	m := auth.NewTOTPManager()
	secret, _, err := m.GenerateSecret("test-user", "TestApp")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	if m.Validate("", secret) {
		t.Error("expected empty code to fail validation")
	}
}

func TestValidateWrongSecret(t *testing.T) {
	m := auth.NewTOTPManager()
	secret, _, err := m.GenerateSecret("test-user", "TestApp")
	if err != nil {
		t.Fatalf("GenerateSecret failed: %v", err)
	}

	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode failed: %v", err)
	}

	if m.Validate(code, "WRONG"+secret) {
		t.Error("expected wrong secret to fail validation")
	}
}

func TestGenerateSecretEmptyUser(t *testing.T) {
	m := auth.NewTOTPManager()
	_, _, err := m.GenerateSecret("", "TestApp")
	if err == nil {
		t.Fatal("expected error when user is empty")
	}
}