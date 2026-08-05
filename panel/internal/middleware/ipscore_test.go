package middleware

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func cannedJSON(body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func setTestHTTPClient(t *testing.T, rt http.RoundTripper) {
	t.Helper()
	orig := httpClient
	httpClient = &http.Client{Transport: rt}
	t.Cleanup(func() { httpClient = orig })
}

func TestIsIPScoreEnabled(t *testing.T) {
	t.Setenv("IP_SCORE_ENABLED", "")
	if IsIPScoreEnabled() {
		t.Error("expected false when env unset")
	}
	t.Setenv("IP_SCORE_ENABLED", "true")
	if !IsIPScoreEnabled() {
		t.Error("expected true when env=true")
	}
}

func TestCheckIP_DisabledOrLoopback(t *testing.T) {
	t.Setenv("IP_SCORE_ENABLED", "false")
	if got := CheckIP("8.8.8.8"); got != (IPScoreResult{}) {
		t.Errorf("expected empty result when disabled, got %+v", got)
	}
	t.Setenv("IP_SCORE_ENABLED", "true")
	if got := CheckIP(""); got != (IPScoreResult{}) {
		t.Errorf("expected empty result for empty ip, got %+v", got)
	}
	if got := CheckIP("127.0.0.1"); got != (IPScoreResult{}) {
		t.Errorf("expected empty result for loopback, got %+v", got)
	}
	if got := CheckIP("::1"); got != (IPScoreResult{}) {
		t.Errorf("expected empty result for IPv6 loopback, got %+v", got)
	}
}

func ipScoreRoundTripper(apiResp, proxyResp, ipapiResp string) rtFunc {
	return func(r *http.Request) (*http.Response, error) {
		path := r.URL.Path
		if strings.Contains(path, "/v2/") {
			return cannedJSON(proxyResp), nil
		}
		// ip-api: /json/8.8.8.8 ; ipapi.co: /8.8.8.8/json/
		if strings.HasPrefix(path, "/json/") {
			return cannedJSON(apiResp), nil
		}
		return cannedJSON(ipapiResp), nil
	}
}

func TestCheckIP_HighThreat(t *testing.T) {
	t.Setenv("IP_SCORE_ENABLED", "true")
	setTestHTTPClient(t, ipScoreRoundTripper(
		`{"country":"RU","isp":"TestISP","proxy":false,"hosting":true}`,
		`{"ip":{"8.8.8.8":{"proxy":"yes","type":"VPN"}}}`,
		`{"security":{"threat_score":80,"is_vpn":true}}`,
	))
	got := CheckIP("8.8.8.8")
	if got.Country != "RU" || got.ISP != "TestISP" {
		t.Errorf("expected country/isp from ip-api, got %+v", got)
	}
	if !got.IsHosting {
		t.Error("expected hosting=true")
	}
	if !got.IsProxy {
		t.Error("expected proxy=true (from proxycheck override)")
	}
	// hosting 30 + proxy 50 + threat 40 + RU country 10 = 130
	if got.Score != 130 {
		t.Errorf("expected score 130, got %d", got.Score)
	}
	if got.Threat != "high" {
		t.Errorf("expected threat high, got %q", got.Threat)
	}
}

func TestCheckIP_MediumThreat(t *testing.T) {
	t.Setenv("IP_SCORE_ENABLED", "true")
	setTestHTTPClient(t, ipScoreRoundTripper(
		`{"country":"US","isp":"","proxy":true,"hosting":false}`,
		`{"ip":{"1.2.3.4":{"proxy":"no"}}}`,
		`{"security":{"threat_score":0}}`,
	))
	got := CheckIP("1.2.3.4")
	if got.Score != 50 {
		t.Errorf("expected score 50 (proxy only), got %d", got.Score)
	}
	if got.Threat != "medium" {
		t.Errorf("expected threat medium, got %q", got.Threat)
	}
}

func TestCheckIP_NoThreat(t *testing.T) {
	t.Setenv("IP_SCORE_ENABLED", "true")
	setTestHTTPClient(t, ipScoreRoundTripper(`{}`, `{}`, `{}`))
	got := CheckIP("5.6.7.8")
	if got.Score != 0 || got.Threat != "" {
		t.Errorf("expected score 0 and no threat, got %+v", got)
	}
}
