package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// CheckSafeBrowsing queries the Google Safe Browsing Lookup API v4.
// Requires a free GSB API key (--gsb-key flag). The key can be obtained
// from https://developers.google.com/safe-browsing/v4/get-started
// Scoring: 10 points — 0 if flagged, 10 if clean.
func CheckSafeBrowsing(domain, apiKey string, timeout time.Duration) *GSBResult {
	result := &GSBResult{MaxScore: 10}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	reqBody := map[string]interface{}{
		"client": map[string]string{
			"clientId":      "domainsvet",
			"clientVersion": "1.0.0",
		},
		"threatInfo": map[string]interface{}{
			"threatTypes": []string{
				"MALWARE",
				"SOCIAL_ENGINEERING",
				"UNWANTED_SOFTWARE",
				"POTENTIALLY_HARMFUL_APPLICATION",
			},
			"platformTypes":    []string{"ANY_PLATFORM"},
			"threatEntryTypes": []string{"URL"},
			"threatEntries": []map[string]string{
				{"url": "https://" + domain + "/"},
				{"url": "http://" + domain + "/"},
				{"url": "https://www." + domain + "/"},
			},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		result.Checks = append(result.Checks, Check{
			Name:   "Google Safe Browsing",
			Status: Skip,
			Detail: "Failed to build request body",
		})
		return result
	}

	url := fmt.Sprintf("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=%s", apiKey)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		result.Checks = append(result.Checks, Check{
			Name:   "Google Safe Browsing",
			Status: Skip,
			Detail: "Failed to build request: " + err.Error(),
		})
		return result
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		result.Checks = append(result.Checks, Check{
			Name:   "Google Safe Browsing",
			Status: Skip,
			Detail: "Request failed: " + err.Error(),
		})
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusForbidden {
		result.Checks = append(result.Checks, Check{
			Name:   "Google Safe Browsing",
			Status: Skip,
			Detail: fmt.Sprintf("API error (HTTP %d) — verify your GSB API key", resp.StatusCode),
		})
		return result
	}

	var gsbResp struct {
		Matches []struct {
			ThreatType string `json:"threatType"`
			ThreatEntry struct {
				URL string `json:"url"`
			} `json:"threatEntry"`
		} `json:"matches"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&gsbResp); err != nil {
		result.Checks = append(result.Checks, Check{
			Name:   "Google Safe Browsing",
			Status: Skip,
			Detail: "Failed to decode API response",
		})
		return result
	}

	if len(gsbResp.Matches) == 0 {
		result.Flagged = false
		result.Score = 10
		result.Checks = append(result.Checks, Check{
			Name:      "Google Safe Browsing",
			Status:    Pass,
			Detail:    "Not flagged in Google Safe Browsing database",
			Points:    10,
			MaxPoints: 10,
		})
		return result
	}

	// Domain is flagged — extract threat types
	seen := map[string]bool{}
	for _, m := range gsbResp.Matches {
		if !seen[m.ThreatType] {
			result.ThreatTypes = append(result.ThreatTypes, m.ThreatType)
			seen[m.ThreatType] = true
		}
	}

	result.Flagged = true
	result.Score = 0
	result.Checks = append(result.Checks, Check{
		Name:      "Google Safe Browsing",
		Status:    Fail,
		Detail:    fmt.Sprintf("FLAGGED: %v — domain is in GSB blocklist", result.ThreatTypes),
		Points:    0,
		MaxPoints: 10,
	})

	return result
}
