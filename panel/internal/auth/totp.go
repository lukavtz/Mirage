package auth

import (
	"bytes"
	"encoding/base64"
	"image/png"

	"github.com/pquerna/otp/totp"
)

type TOTPManager struct{}

func NewTOTPManager() *TOTPManager {
	return &TOTPManager{}
}

func (m *TOTPManager) GenerateSecret(user, issuer string) (secret string, qrBase64 string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: user,
	})
	if err != nil {
		return "", "", err
	}

	img, err := key.Image(256, 256)
	if err != nil {
		return "", "", err
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "", "", err
	}

	qrBase64 = base64.StdEncoding.EncodeToString(buf.Bytes())
	return key.Secret(), qrBase64, nil
}

func (m *TOTPManager) Validate(passcode, secret string) bool {
	return totp.Validate(passcode, secret)
}
