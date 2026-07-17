package middleware

import (
	"context"

	"github.com/user/mirage-panel/internal/auth"
)

type contextKey string

const claimsKey contextKey = "auth.claims"

func ClaimsFromContext(ctx context.Context) *auth.Claims {
	claims, _ := ctx.Value(claimsKey).(*auth.Claims)
	return claims
}

func ContextWithClaims(ctx context.Context, claims *auth.Claims) context.Context {
	return context.WithValue(ctx, claimsKey, claims)
}
