package services

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"zialfi-panel/internal/db"
)

// recordingServer captures every Telegram API request body and path.
type recordingServer struct {
	mu       sync.Mutex
	srv      *httptest.Server
	sends    []map[string]any
	paths    []string
	statuses []int // response status per request
}

func newRecordingBot(t *testing.T) (*SupportBot, *recordingServer, *sql.DB) {
	t.Helper()
	rec := &recordingServer{}
	rec.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		buf := make([]byte, 4096)
		n, _ := r.Body.Read(buf)
		json.Unmarshal(buf[:n], &body)
		rec.mu.Lock()
		rec.paths = append(rec.paths, r.URL.Path)
		rec.sends = append(rec.sends, body)
		rec.statuses = append(rec.statuses, http.StatusOK)
		rec.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(rec.srv.Close)

	d := newBotDB(t)
	bot := NewSupportBot("test:token", d)
	bot.SetAPIBase(rec.srv.URL)
	return bot, rec, d
}

func newBotDB(t *testing.T) *sql.DB {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "mirage-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	d, err := db.OpenDB(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RunMigrations(d, db.MigrationsFS); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func tgMsg(chatID, fromID int64, username, text string) *tgMessage {
	return &tgMessage{
		Chat: tgChat{ID: chatID},
		From: tgFrom{ID: fromID, Username: username},
		Text: text,
	}
}

func (r *recordingServer) lastText() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sends) == 0 {
		return ""
	}
	text, _ := r.sends[len(r.sends)-1]["text"].(string)
	return text
}

func (r *recordingServer) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sends)
}

func TestSupportBot_HandleRegister_CreatesAccount(t *testing.T) {
	bot, rec, d := newRecordingBot(t)
	bot.handleRegister(tgMsg(111, 999001, "newbie", "/register"))

	var username, role string
	err := d.QueryRow("SELECT username, role FROM users WHERE username LIKE 'user_%' AND role = 'worker'").Scan(&username, &role)
	if err != nil {
		t.Fatalf("user not created: %v", err)
	}
	if !strings.HasPrefix(username, "user_") {
		t.Errorf("username = %q, want user_ prefix", username)
	}
	if role != "worker" {
		t.Errorf("role = %q, want worker", role)
	}

	var codes int
	d.QueryRow("SELECT COUNT(*) FROM recovery_codes WHERE user_id = (SELECT id FROM users WHERE username = ?)", username).Scan(&codes)
	if codes != 8 {
		t.Errorf("recovery codes = %d, want 8", codes)
	}

	text := rec.lastText()
	if !strings.Contains(text, "Account Created") {
		t.Errorf("message missing Account Created: %q", text)
	}
	if !strings.Contains(text, username) {
		t.Errorf("message missing username: %q", text)
	}
}

func TestSupportBot_HandleRegister_AlreadyRegistered(t *testing.T) {
	bot, rec, d := newRecordingBot(t)

	// simulate an existing registration: a recovery code whose hash column
	// holds the telegram id (as handleRegister's lookup expects)
	if _, err := d.Exec("INSERT INTO users (id, username, password_hash, role) VALUES ('u1', 'olduser', 'hash', 'worker')"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO recovery_codes (id, user_id, code_hash) VALUES ('rc1', 'u1', '999002')"); err != nil {
		t.Fatal(err)
	}

	bot.handleRegister(tgMsg(111, 999002, "olduser", "/register"))

	text := rec.lastText()
	if !strings.Contains(text, "already have an account") {
		t.Errorf("expected already-registered message, got: %q", text)
	}

	var count int
	d.QueryRow("SELECT COUNT(*) FROM users WHERE telegram_id = '999002'").Scan(&count)
	if count != 0 {
		t.Error("no new user should be created")
	}
}

func TestSupportBot_HandleRegister_DBError(t *testing.T) {
	bot, rec, _ := newRecordingBot(t)
	// close the DB so the insert fails after hashing
	bot.db.Close()

	bot.handleRegister(tgMsg(111, 999003, "u", "/register"))

	text := rec.lastText()
	if !strings.Contains(text, "Something went wrong") {
		t.Errorf("expected error message, got: %q", text)
	}
}

func TestRandomString(t *testing.T) {
	s1 := randomString(16)
	if len(s1) != 16 {
		t.Errorf("len = %d, want 16", len(s1))
	}
	s2 := randomString(16)
	if s1 == s2 {
		t.Error("two random strings should differ")
	}
	const charset = "abcdefghijkmnpqrstuvwxyz23456789"
	for _, c := range s1 {
		if !strings.ContainsRune(charset, c) {
			t.Errorf("char %q outside charset", c)
		}
	}
	if randomString(0) != "" {
		t.Error("expected empty string for n=0")
	}
}

func TestHashPassword(t *testing.T) {
	hash, err := hashPassword("s3cret!")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(hash, "s3cret!") {
		t.Error("hash must not contain plaintext")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("s3cret!")); err != nil {
		t.Errorf("hash should verify: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("wrong")); err == nil {
		t.Error("wrong password should not verify")
	}
}

func TestSupportBot_SetWebhook(t *testing.T) {
	bot, rec, _ := newRecordingBot(t)
	err := bot.SetWebhook("https://example.com/hook")
	if err != nil {
		t.Fatal(err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.paths) == 0 || rec.paths[len(rec.paths)-1] != "/setWebhook" {
		t.Errorf("expected /setWebhook call, got paths %v", rec.paths)
	}
}

func TestSupportBot_SetWebhook_Error(t *testing.T) {
	bot, _, _ := newRecordingBot(t)
	// point at a closed port so the POST fails
	bot.apiBase = "http://localhost:1"
	err := bot.SetWebhook("https://example.com/hook")
	if err == nil {
		t.Fatal("expected error for unreachable API")
	}
}

func TestSupportBot_HandleLicense_Valid(t *testing.T) {
	bot, rec, d := newRecordingBot(t)
	if _, err := d.Exec("INSERT INTO purchases (id, user_id, product_id, license_key, expires_at) VALUES ('p1', 'u1', 'prod1', 'LIC-KEY-1', '2027-01-01')"); err != nil {
		t.Fatal(err)
	}

	bot.handleLicense(tgMsg(111, 1, "u", "/license LIC-KEY-1"))
	text := rec.lastText()
	if !strings.Contains(text, "License:") || !strings.Contains(text, "LIC-KEY-1") {
		t.Errorf("expected license message, got: %q", text)
	}
	if !strings.Contains(text, "starter") {
		t.Errorf("expected tier in message, got: %q", text)
	}
}

func TestSupportBot_HandleLicense_NoKey(t *testing.T) {
	bot, rec, _ := newRecordingBot(t)
	bot.handleLicense(tgMsg(111, 1, "u", "/license"))
	if !strings.Contains(rec.lastText(), "Usage: /license") {
		t.Errorf("expected usage message, got: %q", rec.lastText())
	}
}

func TestSupportBot_HandleUpdate_InvalidJSON(t *testing.T) {
	bot, rec, _ := newRecordingBot(t)
	bot.HandleUpdate([]byte("{not json"))
	if rec.count() != 0 {
		t.Error("no send should happen for invalid JSON")
	}
	bot.HandleUpdate([]byte(`{"message": null}`))
	if rec.count() != 0 {
		t.Error("no send should happen for null message")
	}
}

func TestSupportBot_HandleBuy_DBError(t *testing.T) {
	bot, rec, _ := newRecordingBot(t)
	bot.db.Close()
	bot.HandleUpdate([]byte(`{"message":{"chat":{"id":1},"from":{"id":1,"username":"u"},"text":"/buy pro"}}`))
	if !strings.Contains(rec.lastText(), "Something went wrong") {
		t.Errorf("expected error message, got: %q", rec.lastText())
	}
}

func TestSupportBot_Send_NetworkError(t *testing.T) {
	bot, rec, _ := newRecordingBot(t)
	bot.apiBase = "http://localhost:1"
	bot.send(111, "hello")
	if rec.count() != 0 {
		t.Error("no request should be recorded when API unreachable")
	}
}

func TestSupportBot_HandleUpdate_Start(t *testing.T) {
	bot, rec, _ := newRecordingBot(t)
	bot.HandleUpdate([]byte(`{"message":{"chat":{"id":1},"from":{"id":1,"username":"u"},"text":"/start"}}`))
	if !strings.Contains(rec.lastText(), "Mirage Support Bot") {
		t.Errorf("expected welcome text, got: %q", rec.lastText())
	}
}

func TestSupportBot_Send_EncodesChatID(t *testing.T) {
	bot, rec, _ := newRecordingBot(t)
	bot.send(555, "payload")
	rec.mu.Lock()
	defer rec.mu.Unlock()
	var buf bytes.Buffer
	_ = buf
	if len(rec.sends) == 0 {
		t.Fatal("expected a send")
	}
	last := rec.sends[len(rec.sends)-1]
	if last["chat_id"] != float64(555) {
		t.Errorf("chat_id = %v, want 555", last["chat_id"])
	}
	if last["text"] != "payload" {
		t.Errorf("text = %v, want payload", last["text"])
	}
}
