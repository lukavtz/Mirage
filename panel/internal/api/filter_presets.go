package api

import (
	"database/sql"
	"net/http"
)

type FilterPresetsHandler struct {
	db *sql.DB
}

func NewFilterPresetsHandler(db *sql.DB) *FilterPresetsHandler {
	return &FilterPresetsHandler{db: db}
}

type FilterPreset struct {
	Name    string   `json:"name"`
	Domains []string `json:"domains"`
}

func (h *FilterPresetsHandler) List(w http.ResponseWriter, r *http.Request) {
	presets := []FilterPreset{
		{
			Name:    "Steam",
			Domains: []string{"steamcommunity.com", "store.steampowered.com", "help.steampowered.com"},
		},
		{
			Name:    "Crypto",
			Domains: []string{"binance.com", "coinbase.com", "kraken.com", "bybit.com", "okx.com", "huobi.com", "crypto.com", "gemini.com", "kucoin.com"},
		},
		{
			Name:    "Email",
			Domains: []string{"mail.google.com", "outlook.live.com", "yahoo.com", "protonmail.com", "mail.yandex.com", "tutanota.com"},
		},
		{
			Name:    "Social",
			Domains: []string{"facebook.com", "twitter.com", "instagram.com", "reddit.com", "discord.com", "tiktok.com", "linkedin.com"},
		},
		{
			Name:    "Gaming",
			Domains: []string{"epicgames.com", "ubisoft.com", "ea.com", "battle.net", "riotgames.com", "minecraft.net", "roblox.com"},
		},
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"presets": presets,
	})
}
