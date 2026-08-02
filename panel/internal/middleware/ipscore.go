package middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

type IPScoreResult struct {
	Score     int    `json:"score"`
	ISP       string `json:"isp,omitempty"`
	Country   string `json:"country,omitempty"`
	IsProxy   bool   `json:"is_proxy"`
	IsHosting bool   `json:"is_hosting"`
	Threat    string `json:"threat,omitempty"`
}

type ipAPIData struct {
	Country string `json:"country"`
	ISP     string `json:"isp"`
	Proxy   bool   `json:"proxy"`
	Hosting bool   `json:"hosting"`
}

type ipapiData struct {
	Security struct {
		ThreatScore int  `json:"threat_score"`
		IsVPN       bool `json:"is_vpn"`
	} `json:"security"`
}

type proxycheckData struct {
	IP map[string]struct {
		Proxy string `json:"proxy"`
		Type  string `json:"type"`
	} `json:"ip"`
}

var httpClient = &http.Client{Timeout: 5 * time.Second}

func IsIPScoreEnabled() bool {
	return os.Getenv("IP_SCORE_ENABLED") == "true"
}

func CheckIP(ip string) IPScoreResult {
	if ip == "" || ip == "127.0.0.1" || ip == "::1" || !IsIPScoreEnabled() {
		return IPScoreResult{}
	}

	var (
		apiData     ipAPIData
		ipapi       ipapiData
		proxycheck  proxycheckData
		wg          sync.WaitGroup
	)

	wg.Add(3)

	go func() {
		defer wg.Done()
		if resp, err := httpClient.Get(fmt.Sprintf("https://ip-api.com/json/%s?fields=country,isp,proxy,hosting", ip)); err == nil {
			defer resp.Body.Close()
			json.NewDecoder(resp.Body).Decode(&apiData)
		}
	}()

	go func() {
		defer wg.Done()
		if resp, err := httpClient.Get(fmt.Sprintf("https://ipapi.co/%s/json/", ip)); err == nil {
			defer resp.Body.Close()
			json.NewDecoder(resp.Body).Decode(&ipapi)
		}
	}()

	go func() {
		defer wg.Done()
		if resp, err := httpClient.Get(fmt.Sprintf("https://proxycheck.io/v2/%s?key=&vpn=1", ip)); err == nil {
			defer resp.Body.Close()
			json.NewDecoder(resp.Body).Decode(&proxycheck)
		}
	}()

	wg.Wait()

	result := IPScoreResult{
		Country:   apiData.Country,
		ISP:       apiData.ISP,
		IsProxy:   apiData.Proxy,
		IsHosting: apiData.Hosting,
	}

	if entry, ok := proxycheck.IP[ip]; ok {
		if entry.Proxy == "yes" {
			result.IsProxy = true
		}
	}

	if result.IsHosting {
		result.Score += 30
	}
	if result.IsProxy {
		result.Score += 50
	}
	if ipapi.Security.ThreatScore > 50 {
		result.Score += 40
	}
	switch result.Country {
	case "RU", "UA", "BY", "KZ", "MD", "AZ", "AM", "UZ", "TJ", "TM", "KG":
		result.Score += 10
	}

	if result.Score > 60 {
		result.Threat = "high"
	} else if result.Score > 30 {
		result.Threat = "medium"
	}

	return result
}
