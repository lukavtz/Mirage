package api

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"zialfi-panel/internal/db"
)

type FilterPresetsHandler struct {
	db *sql.DB
	provider     db.ProviderType
}

func NewFilterPresetsHandler(db *sql.DB, provider db.ProviderType) *FilterPresetsHandler {
	return &FilterPresetsHandler{db: db, provider: provider}
}

type FilterPreset struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

func (h *FilterPresetsHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(h.db, h.provider, "SELECT name, domains FROM filter_presets ORDER BY created_at")
	if err == nil {
		defer rows.Close()
		presets := make([]FilterPreset, 0)
		for rows.Next() {
			var p FilterPreset
			var domainsJSON string
			if err := rows.Scan(&p.Name, &domainsJSON); err != nil {
				continue
			}
			json.Unmarshal([]byte(domainsJSON), &p.Domains)
			presets = append(presets, p)
		}
		if len(presets) > 0 {
			writeJSON(w, http.StatusOK, map[string]any{"presets": presets})
			return
		}
	}

	// Fallback if table is empty or missing
	presets := []FilterPreset{
		{Name: "Steam", Domains: []string{"steamcommunity.com", "store.steampowered.com", "help.steampowered.com"}},
		{Name: "Crypto", Domains: []string{"binance.com", "coinbase.com", "kraken.com", "bybit.com", "okx.com", "huobi.com", "crypto.com", "gemini.com", "kucoin.com"}},
		{Name: "Email", Domains: []string{"mail.google.com", "outlook.live.com", "yahoo.com", "protonmail.com", "mail.yandex.com", "tutanota.com"}},
		{Name: "Social", Domains: []string{"facebook.com", "twitter.com", "instagram.com", "reddit.com", "discord.com", "tiktok.com", "linkedin.com"}},
		{Name: "Gaming", Domains: []string{"epicgames.com", "ubisoft.com", "ea.com", "battle.net", "riotgames.com", "minecraft.net", "roblox.com"}},
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"presets": presets,
	})
}
