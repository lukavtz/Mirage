package bot

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"zialfi-panel/internal/testutil"
)

// recordingAPI stands in for api.telegram.org and records every call.
type recordingAPI struct {
	mu      sync.Mutex
	paths   []string
	bodies  []map[string]any
	handler func(w http.ResponseWriter, r *http.Request)
}

func (a *recordingAPI) record(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	dec := json.NewDecoder(r.Body)
	_ = dec.Decode(&body)
	a.mu.Lock()
	a.paths = append(a.paths, r.URL.Path)
	a.bodies = append(a.bodies, body)
	a.mu.Unlock()
	if a.handler != nil {
		a.handler(w, r)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"ok":true}`)
}

func (a *recordingAPI) count(path string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, p := range a.paths {
		if p == path {
			n++
		}
	}
	return n
}

func (a *recordingAPI) lastBody() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.bodies) == 0 {
		return nil
	}
	return a.bodies[len(a.bodies)-1]
}

// anyBody returns the first recorded body whose "text" contains needle.
func (a *recordingAPI) anyBody(needle string) (map[string]any, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, b := range a.bodies {
		if text, _ := b["text"].(string); strings.Contains(text, needle) {
			return b, true
		}
	}
	return nil, false
}

func openBotDB(t *testing.T) *sql.DB {
	t.Helper()
	return testutil.OpenTestDB(t)
}

func newTestBot(t *testing.T) (*Bot, *recordingAPI, *sql.DB) {
	t.Helper()
	api := &recordingAPI{}
	ts := httptest.NewServer(http.HandlerFunc(api.record))
	t.Cleanup(ts.Close)

	d := openBotDB(t)
	b := &Bot{
		token:    "test:token",
		db:       d,
		apiBase:  ts.URL,
		panelURL: "http://localhost:8080",
	}
	return b, api, d
}

func TestBot_New_ReadsSettings(t *testing.T) {
	d := openBotDB(t)
	if _, err := d.Exec("INSERT INTO settings (key, value) VALUES ('telegram_token','db-token'), ('bot_admin_chat_id','424242'), ('panel_url','https://panel.example') ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"); err != nil {
		t.Fatal(err)
	}
	b := New(d)
	if b.token != "db-token" {
		t.Errorf("token = %q, want db-token", b.token)
	}
	if b.adminChatID != "424242" {
		t.Errorf("adminChatID = %q", b.adminChatID)
	}
	if b.panelURL != "https://panel.example" {
		t.Errorf("panelURL = %q", b.panelURL)
	}
}

func TestBot_New_EnvTokenWins(t *testing.T) {
	t.Setenv("TELEGRAM_BOT_TOKEN", "env-token")
	d := openBotDB(t)
	b := New(d)
	if b.token != "env-token" {
		t.Errorf("token = %q, want env-token", b.token)
	}
}

func TestBot_New_DefaultPanelURL(t *testing.T) {
	d := openBotDB(t)
	b := New(d)
	if b.panelURL != "http://localhost:8080" {
		t.Errorf("panelURL = %q, want default", b.panelURL)
	}
}

func TestBot_Start_NoToken(t *testing.T) {
	b := &Bot{token: ""}
	b.Start() // must return immediately
}

func TestBot_getUpdates_Success(t *testing.T) {
	b, api, _ := newTestBot(t)
	api.handler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ok":true,"result":[{"update_id":1,"message":{"message_id":1,"chat":{"id":1},"from":{"id":1,"username":"u"},"text":"hi"}}]}`)
	}
	updates, err := b.getUpdates()
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(updates))
	}
}

func TestBot_getUpdates_NotOK(t *testing.T) {
	b, api, _ := newTestBot(t)
	api.handler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ok":false}`)
	}
	if _, err := b.getUpdates(); err == nil {
		t.Fatal("expected error for ok=false")
	}
}

func TestBot_getUpdates_InvalidJSON(t *testing.T) {
	b, api, _ := newTestBot(t)
	api.handler = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `not-json`)
	}
	if _, err := b.getUpdates(); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestBot_getUpdates_NetworkError(t *testing.T) {
	b := &Bot{apiBase: "http://localhost:1", offset: 0}
	if _, err := b.getUpdates(); err == nil {
		t.Fatal("expected network error")
	}
}

func TestBot_handleStart_NewUser(t *testing.T) {
	b, api, d := newTestBot(t)
	b.handleUpdate(tgUpdate{Message: &tgMessage{
		MessageID: 7,
		Chat:      tgChat{ID: 100},
		From:      tgFrom{ID: 5001, Username: "fresh"},
		Text:      "/start",
	}})

	var username string
	err := d.QueryRow("SELECT username FROM users WHERE telegram_id = '5001'").Scan(&username)
	if err != nil {
		t.Fatalf("user not created: %v", err)
	}
	if !strings.HasPrefix(username, "user_") {
		t.Errorf("username = %q", username)
	}
	var codes int
	d.QueryRow("SELECT COUNT(*) FROM recovery_codes rc JOIN users u ON u.id = rc.user_id WHERE u.telegram_id = '5001'").Scan(&codes)
	if codes != 8 {
		t.Errorf("recovery codes = %d, want 8", codes)
	}
	if n := api.count("/sendMessage"); n != 1 {
		t.Errorf("sendMessage calls = %d, want 1", n)
	}
	body := api.lastBody()
	text, _ := body["text"].(string)
	if !strings.Contains(text, "Account Created") {
		t.Errorf("message missing Account Created: %q", text)
	}
	if _, ok := body["reply_markup"]; !ok {
		t.Error("expected reply_markup on registration message")
	}
}

func TestBot_handleStart_ExistingUser(t *testing.T) {
	b, api, d := newTestBot(t)
	if _, err := d.Exec("INSERT INTO users (id, username, password_hash, role, telegram_id) VALUES ('u1','olduser','hash','worker','5002')"); err != nil {
		t.Fatal(err)
	}
	b.handleUpdate(tgUpdate{Message: &tgMessage{
		MessageID: 7,
		Chat:      tgChat{ID: 100},
		From:      tgFrom{ID: 5002, Username: "olduser"},
		Text:      "/start",
	}})
	if n := api.count("/sendMessage"); n != 1 {
		t.Errorf("sendMessage calls = %d, want 1", n)
	}
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "Welcome back") {
		t.Errorf("expected welcome-back message, got: %q", text)
	}
	var count int
	d.QueryRow("SELECT COUNT(*) FROM users WHERE telegram_id = '5002'").Scan(&count)
	if count != 1 {
		t.Error("no new user should be created for existing user")
	}
}

func TestBot_handleStart_DBError(t *testing.T) {
	b, api, _ := newTestBot(t)
	b.db.Close()
	b.handleUpdate(tgUpdate{Message: &tgMessage{
		MessageID: 7,
		Chat:      tgChat{ID: 100},
		From:      tgFrom{ID: 5003, Username: "u"},
		Text:      "/start",
	}})
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "Something went wrong") {
		t.Errorf("expected error message, got: %q", text)
	}
}

func TestBot_handleUpdate_Noop(t *testing.T) {
	b, api, _ := newTestBot(t)
	b.handleUpdate(tgUpdate{Message: &tgMessage{
		Chat: tgChat{ID: 1}, From: tgFrom{ID: 1, Username: "u"}, Text: "just chatting",
	}})
	if len(api.paths) != 0 {
		t.Error("no API calls expected for non-command message")
	}
}

func TestBot_handleCallback_Saved(t *testing.T) {
	b, api, d := newTestBot(t)
	if _, err := d.Exec("INSERT INTO users (id, username, password_hash, role) VALUES ('newid','saveduser','hash','worker')"); err != nil {
		t.Fatal(err)
	}
	b.handleUpdate(tgUpdate{Callback: &tgCallback{
		ID:      "cb1",
		Message: &tgMessage{MessageID: 9, Chat: tgChat{ID: 100}, From: tgFrom{ID: 1, Username: "u"}, Text: "x"},
		From:    tgFrom{ID: 1, Username: "u"},
		Data:    "saved:newid",
	}})
	if api.count("/answerCallbackQuery") != 1 {
		t.Error("expected answerCallbackQuery")
	}
	if api.count("/editMessageText") != 1 {
		t.Error("expected editMessageText for main menu")
	}
}

func TestBot_handleCallback_MainMenu(t *testing.T) {
	b, api, d := newTestBot(t)
	if _, err := d.Exec("INSERT INTO users (id, username, password_hash, role, telegram_id) VALUES ('u2','menuuser','hash','worker','6001')"); err != nil {
		t.Fatal(err)
	}
	b.handleUpdate(tgUpdate{Callback: &tgCallback{
		ID:      "cb2",
		Message: &tgMessage{MessageID: 9, Chat: tgChat{ID: 100}, From: tgFrom{ID: 1, Username: "u"}, Text: "x"},
		From:    tgFrom{ID: 6001, Username: "menuuser"},
		Data:    "menu:main",
	}})
	if api.count("/editMessageText") != 1 {
		t.Error("expected editMessageText")
	}
}

func TestBot_handleCallback_Stats(t *testing.T) {
	b, api, d := newTestBot(t)
	if _, err := d.Exec("INSERT INTO sessions (id, build_id, hwid) VALUES ('s1','','hw')"); err != nil {
		t.Fatal(err)
	}
	b.handleUpdate(tgUpdate{Callback: &tgCallback{
		ID:      "cb3",
		Message: &tgMessage{MessageID: 9, Chat: tgChat{ID: 100}, From: tgFrom{ID: 1, Username: "u"}, Text: "x"},
		From:    tgFrom{ID: 1, Username: "u"},
		Data:    "menu:stats",
	}})
	body := api.lastBody()
	text, _ := body["text"].(string)
	if !strings.Contains(text, "Statistics") {
		t.Errorf("expected stats text, got: %q", text)
	}
}

func TestBot_handleCallback_Account(t *testing.T) {
	b, api, d := newTestBot(t)
	if _, err := d.Exec("INSERT INTO users (id, username, password_hash, role, telegram_id) VALUES ('u3','accuser','hash','admin','7001')"); err != nil {
		t.Fatal(err)
	}
	b.handleUpdate(tgUpdate{Callback: &tgCallback{
		ID:      "cb4",
		Message: &tgMessage{MessageID: 9, Chat: tgChat{ID: 100}, From: tgFrom{ID: 1, Username: "u"}, Text: "x"},
		From:    tgFrom{ID: 7001, Username: "accuser"},
		Data:    "menu:account",
	}})
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "My Account") || !strings.Contains(text, "accuser") {
		t.Errorf("expected account text, got: %q", text)
	}
}

func TestBot_handleCallback_Account_NotFound(t *testing.T) {
	b, api, _ := newTestBot(t)
	b.handleUpdate(tgUpdate{Callback: &tgCallback{
		ID:      "cb5",
		Message: &tgMessage{MessageID: 9, Chat: tgChat{ID: 100}, From: tgFrom{ID: 1, Username: "u"}, Text: "x"},
		From:    tgFrom{ID: 99999, Username: "ghost"},
		Data:    "menu:account",
	}})
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "Account not found") {
		t.Errorf("expected account-not-found text, got: %q", text)
	}
}

func TestBot_handleCallback_Buy(t *testing.T) {
	b, api, _ := newTestBot(t)
	b.handleUpdate(tgUpdate{Callback: &tgCallback{
		ID:      "cb6",
		Message: &tgMessage{MessageID: 9, Chat: tgChat{ID: 100}, From: tgFrom{ID: 1, Username: "u"}, Text: "x"},
		From:    tgFrom{ID: 1, Username: "u"},
		Data:    "menu:buy",
	}})
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "Choose your plan") {
		t.Errorf("expected buy menu text, got: %q", text)
	}
}

func TestBot_handleCallback_Docs(t *testing.T) {
	b, api, _ := newTestBot(t)
	b.handleUpdate(tgUpdate{Callback: &tgCallback{
		ID:      "cb7",
		Message: &tgMessage{MessageID: 9, Chat: tgChat{ID: 100}, From: tgFrom{ID: 1, Username: "u"}, Text: "x"},
		From:    tgFrom{ID: 1, Username: "u"},
		Data:    "menu:docs",
	}})
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "Documentation") {
		t.Errorf("expected docs text, got: %q", text)
	}
}

func TestBot_handleCallback_Support(t *testing.T) {
	b, api, _ := newTestBot(t)
	b.handleUpdate(tgUpdate{Callback: &tgCallback{
		ID:      "cb8",
		Message: &tgMessage{MessageID: 9, Chat: tgChat{ID: 100}, From: tgFrom{ID: 1, Username: "u"}, Text: "x"},
		From:    tgFrom{ID: 1, Username: "u"},
		Data:    "menu:support",
	}})
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "Support") {
		t.Errorf("expected support text, got: %q", text)
	}
}

func TestBot_handleCallback_Settings(t *testing.T) {
	b, api, _ := newTestBot(t)
	b.handleUpdate(tgUpdate{Callback: &tgCallback{
		ID:      "cb9",
		Message: &tgMessage{MessageID: 9, Chat: tgChat{ID: 100}, From: tgFrom{ID: 1, Username: "u"}, Text: "x"},
		From:    tgFrom{ID: 1, Username: "u"},
		Data:    "menu:settings",
	}})
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "Settings") {
		t.Errorf("expected settings text, got: %q", text)
	}
}

func TestBot_handleCallback_Lang(t *testing.T) {
	b, api, _ := newTestBot(t)
	b.handleUpdate(tgUpdate{Callback: &tgCallback{
		ID:      "cb10",
		Message: &tgMessage{MessageID: 9, Chat: tgChat{ID: 100}, From: tgFrom{ID: 1, Username: "u"}, Text: "x"},
		From:    tgFrom{ID: 1, Username: "u"},
		Data:    "lang:ru",
	}})
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "Русский") {
		t.Errorf("expected Russian language text, got: %q", text)
	}
}

func TestBot_handleCallback_BuyConfirm(t *testing.T) {
	b, api, _ := newTestBot(t)
	b.handleUpdate(tgUpdate{Callback: &tgCallback{
		ID:      "cb11",
		Message: &tgMessage{MessageID: 9, Chat: tgChat{ID: 100}, From: tgFrom{ID: 1, Username: "u"}, Text: "x"},
		From:    tgFrom{ID: 1, Username: "u"},
		Data:    "buy:pro",
	}})
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "Confirm purchase") {
		t.Errorf("expected confirm text, got: %q", text)
	}
}

func TestBot_handleBuyConfirm_UnknownTier(t *testing.T) {
	b, api, _ := newTestBot(t)
	b.handleBuyConfirm(100, 9, "enterprise", 1)
	if len(api.paths) != 0 {
		t.Error("no API calls expected for unknown tier")
	}
}

func TestBot_handleCallback_BuySubmit(t *testing.T) {
	b, api, d := newTestBot(t)
	if _, err := d.Exec("INSERT INTO users (id, username, password_hash, role, telegram_id) VALUES ('u5','buyuser','hash','worker','8001')"); err != nil {
		t.Fatal(err)
	}
	b.handleUpdate(tgUpdate{Callback: &tgCallback{
		ID:      "cb12",
		Message: &tgMessage{MessageID: 9, Chat: tgChat{ID: 100}, From: tgFrom{ID: 1, Username: "u"}, Text: "x"},
		From:    tgFrom{ID: 8001, Username: "buyuser"},
		Data:    "confirm:starter",
	}})
	var status string
	err := d.QueryRow("SELECT status FROM purchase_requests WHERE user_id = 'u5'").Scan(&status)
	if err != nil {
		t.Fatalf("purchase request not created: %v", err)
	}
	if status != "pending" {
		t.Errorf("status = %q, want pending", status)
	}
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "Request submitted") {
		t.Errorf("expected confirmation text, got: %q", text)
	}
}

func TestBot_handleBuySubmit_WithAdminChat(t *testing.T) {
	b, api, d := newTestBot(t)
	b.adminChatID = "424242"
	if _, err := d.Exec("INSERT INTO users (id, username, password_hash, role, telegram_id) VALUES ('u6','adminbuy','hash','worker','8002')"); err != nil {
		t.Fatal(err)
	}
	b.handleBuySubmit(100, 9, "team", 8002)
	if api.count("/sendMessage") != 1 {
		t.Error("expected admin notification via sendMessage")
	}
	var count int
	d.QueryRow("SELECT COUNT(*) FROM purchase_requests WHERE user_id = 'u6'").Scan(&count)
	if count != 1 {
		t.Error("expected 1 purchase request")
	}
}

func TestBot_handleBuySubmit_AccountNotFound(t *testing.T) {
	b, api, _ := newTestBot(t)
	b.handleBuySubmit(100, 9, "starter", 99999)
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "Account not found") {
		t.Errorf("expected account-not-found text, got: %q", text)
	}
}

func TestBot_handleCallback_Approve(t *testing.T) {
	b, api, d := newTestBot(t)
	if _, err := d.Exec("INSERT INTO users (id, username, password_hash, role, telegram_id) VALUES ('u7','appuser','hash','worker','9001')"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO purchase_requests (id, user_id, tier, status) VALUES ('req-000001','u7','pro','pending')"); err != nil {
		t.Fatal(err)
	}
	b.handleUpdate(tgUpdate{Callback: &tgCallback{
		ID:      "cb13",
		Message: &tgMessage{MessageID: 9, Chat: tgChat{ID: 100}, From: tgFrom{ID: 1, Username: "u"}, Text: "x"},
		From:    tgFrom{ID: 1, Username: "admin"},
		Data:    "approve:req-000001",
	}})
	var status string
	d.QueryRow("SELECT status FROM purchase_requests WHERE id = 'req-000001'").Scan(&status)
	if status != "approved" {
		t.Errorf("status = %q, want approved", status)
	}
	if api.count("/sendMessage") != 1 {
		t.Error("expected user notification via sendMessage")
	}
	if _, ok := api.anyBody("Subscription activated"); !ok {
		t.Error("expected activation text in a sent message")
	}
}

func TestBot_handleApprove_NotFound(t *testing.T) {
	b, api, _ := newTestBot(t)
	b.handleApprove(100, 9, "", 1)
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "Request not found") {
		t.Errorf("expected request-not-found text, got: %q", text)
	}
	b.handleApprove(100, 9, "missing", 1)
	text, _ = api.lastBody()["text"].(string)
	if !strings.Contains(text, "Request not found") {
		t.Errorf("expected request-not-found text, got: %q", text)
	}
}

func TestBot_handleCallback_Reject(t *testing.T) {
	b, api, d := newTestBot(t)
	if _, err := d.Exec("INSERT INTO users (id, username, password_hash, role) VALUES ('u8','rejuser','hash','worker')"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO purchase_requests (id, user_id, tier, status) VALUES ('req-000002','u8','starter','pending')"); err != nil {
		t.Fatal(err)
	}
	b.handleUpdate(tgUpdate{Callback: &tgCallback{
		ID:      "cb14",
		Message: &tgMessage{MessageID: 9, Chat: tgChat{ID: 100}, From: tgFrom{ID: 1, Username: "u"}, Text: "x"},
		From:    tgFrom{ID: 1, Username: "admin"},
		Data:    "reject:req-000002",
	}})
	var status string
	d.QueryRow("SELECT status FROM purchase_requests WHERE id = 'req-000002'").Scan(&status)
	if status != "rejected" {
		t.Errorf("status = %q, want rejected", status)
	}
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "Rejected") {
		t.Errorf("expected rejected text, got: %q", text)
	}
}

func TestBot_handleReject_Success(t *testing.T) {
	b, _, d := newTestBot(t)
	if _, err := d.Exec("INSERT INTO users (id, username, password_hash, role) VALUES ('u9','legrej','hash','worker')"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO purchase_requests (id, user_id, tier, status) VALUES ('req-000003','u9','team','pending')"); err != nil {
		t.Fatal(err)
	}
	b.handleReject(100, 9, "req-000003")
	var status string
	d.QueryRow("SELECT status FROM purchase_requests WHERE id = 'req-000003'").Scan(&status)
	if status != "rejected" {
		t.Errorf("status = %q, want rejected", status)
	}
}

func TestBot_handleApprove_NoTelegramID(t *testing.T) {
	b, api, d := newTestBot(t)
	if _, err := d.Exec("INSERT INTO users (id, username, password_hash, role) VALUES ('u10','notg','hash','worker')"); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO purchase_requests (id, user_id, tier, status) VALUES ('req-000004','u10','pro','pending')"); err != nil {
		t.Fatal(err)
	}
	b.handleApprove(100, 9, "req-4", 1)
	if api.count("/sendMessage") != 0 {
		t.Error("no user notification expected")
	}
	if api.count("/editMessageText") != 1 {
		t.Error("expected editMessageText")
	}
}

func TestBot_sendMessage_NetworkError(t *testing.T) {
	b := &Bot{apiBase: "http://localhost:1"}
	b.sendMessage(1, "hi", "")
	b.sendMessageMarkup(1, "hi", `{"inline_keyboard":[]}`)
	b.editMessageMarkup(1, 2, "hi", "")
	b.answerCallback("cb")
}

func TestBot_inlineKeyboard(t *testing.T) {
	kb := inlineKeyboard(
		[]InlineButton{{Text: "A", Data: "a"}},
		[]InlineButton{{Text: "B", Data: "b"}},
	)
	var parsed InlineKeyboardMarkup
	if err := json.Unmarshal([]byte(kb), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.InlineKeyboard) != 2 {
		t.Errorf("rows = %d, want 2", len(parsed.InlineKeyboard))
	}
	if parsed.InlineKeyboard[0][0].Text != "A" {
		t.Errorf("unexpected button: %+v", parsed.InlineKeyboard[0][0])
	}
}

func TestBot_RandomString(t *testing.T) {
	s1 := randomString(12)
	if len(s1) != 12 {
		t.Errorf("len = %d, want 12", len(s1))
	}
	s2 := randomString(12)
	if s1 == s2 {
		t.Error("two random strings should differ")
	}
	const charset = "abcdefghijkmnpqrstuvwxyz23456789"
	for _, c := range s1 {
		if !strings.ContainsRune(charset, c) {
			t.Errorf("char %q outside charset", c)
		}
	}
}

func TestBot_handleStats(t *testing.T) {
	b, api, d := newTestBot(t)
	_ = api
	if _, err := d.Exec("INSERT INTO sessions (id, build_id, hwid) VALUES ('s1','','hw')"); err != nil {
		t.Fatal(err)
	}
	b.handleStats(100, 9)
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "Statistics") {
		t.Errorf("expected stats text, got: %q", text)
	}
}

func TestBot_sendMainMenu(t *testing.T) {
	b, api, _ := newTestBot(t)
	b.sendMainMenu(100, 0, "welcomeuser")
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "Welcome back") {
		t.Errorf("expected welcome-back text, got: %q", text)
	}
}

func TestBot_handleBuySubmit_DBError(t *testing.T) {
	b, api, _ := newTestBot(t)
	b.db.Close()
	b.handleBuySubmit(100, 9, "starter", 12345)
	text, _ := api.lastBody()["text"].(string)
	if !strings.Contains(text, "Account not found") && !strings.Contains(text, "Something went wrong") {
		t.Errorf("expected error text, got: %q", text)
	}
}
