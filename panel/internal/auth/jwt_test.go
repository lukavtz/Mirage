package auth_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"zialfi-panel/internal/auth"
)

func TestGenerateAndValidate(t *testing.T) {
	secret := "test-secret-key"
	tokenStr, expiresAt, err := auth.GenerateToken("user-42", "admin", secret, "", 0)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}
	if tokenStr == "" {
		t.Fatal("expected non-empty token")
	}
	if expiresAt.IsZero() {
		t.Fatal("expected non-zero expiry time")
	}

	claims, err := auth.ValidateToken(tokenStr, secret)
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	if claims.UserID != "user-42" {
		t.Errorf("expected UserID 'user-42', got %q", claims.UserID)
	}
	if claims.Role != "admin" {
		t.Errorf("expected Role 'admin', got %q", claims.Role)
	}
}

func TestExpiredToken(t *testing.T) {
	claims := &auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
		UserID: "user-1",
		Role:   "admin",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = auth.ValidateToken(tokenStr, "secret")
	if err == nil {
		t.Error("expected error for expired token")
	}
}

func TestWrongSecret(t *testing.T) {
	tokenStr, _, err := auth.GenerateToken("user-1", "admin", "secret-a", "", 0)
	if err != nil {
		t.Fatal(err)
	}

	_, err = auth.ValidateToken(tokenStr, "secret-b")
	if err == nil {
		t.Error("expected error when validating with wrong secret")
	}
}

func TestMalformedToken(t *testing.T) {
	_, err := auth.ValidateToken("not.a.token", "secret")
	if err == nil {
		t.Error("expected error for malformed token")
	}
}

func TestAlgorithmConfusion(t *testing.T) {
	secret := "test-secret"
	tokenStr, _, err := auth.GenerateToken("user-1", "admin", secret, "", 0)
	if err != nil {
		t.Fatal(err)
	}

	_, err = auth.ValidateToken(tokenStr, secret)
	if err != nil {
		t.Fatalf("expected valid token to pass: %v", err)
	}

	noneToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
		"eyJ1aWQiOiJ1c2VyLTEiLCJyb2xlIjoiYWRtaW4iLCJzdWIiOiIiLCJhdWQiOiIiLCJpc3MiOiIiLCJpYXQiOjAsImV4cCI6OTk5OTk5OTk5OSwibmJmIjowfQ."

	_, err = auth.ValidateToken(noneToken, secret)
	if err == nil {
		t.Error("expected error for alg=none token")
	}
}

func TestHashAndCheckPassword(t *testing.T) {
	password := "password123"
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}

	if !auth.CheckPassword(password, hash) {
		t.Error("expected CheckPassword to return true for correct password")
	}

	if auth.CheckPassword("wrong", hash) {
		t.Error("expected CheckPassword to return false for wrong password")
	}
}

func TestHashPasswordUniqueness(t *testing.T) {
	password := "password123"
	hash1, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	hash2, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}

	if hash1 == hash2 {
		t.Error("expected different hashes for same password (bcrypt salts)")
	}
}
