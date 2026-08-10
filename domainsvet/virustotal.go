package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// CheckVirusTotal queries the VirusTotal v3 API for domain reputation.
// Requires a free or paid VT API key (--vt-key flag).
// Scoring: 10 points — scaled by detection count.
func CheckVirusTotal(domain, apiKey string, timeout time.Duration) *VTResult {
	result := &VTResult{MaxScore: 10}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		result.Checks = append(result.Checks, Check{
			Name:   "VirusTotal",
			Status: Skip,
			Detail: "Failed to build request: " + err.Error(),
		})
		return result
	}
	req.Header.Set("x-apikey", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		result.Checks = append(result.Checks, Check{
			Name:   "VirusTotal",
			Status: Skip,
			Detail: "Request failed: " + err.Error(),
		})
		return result
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		result.Checks = append(result.Checks, Check{
			Name:   "VirusTotal",
			Status: Skip,
			Detail: "Invalid API key",
		})
		return result
	case http.StatusNotFound:
		// Domain unknown to VT — not necessarily bad for brand new domains
		result.Score = 8
		result.Checks = append(result.Checks, Check{
			Name:      "VirusTotal",
			Status:    Info,
			Detail:    "Domain not yet in VT database — monitor after deployment",
			Points:    8,
			MaxPoints: 10,
		})
		return result
	case http.StatusTooManyRequests:
		result.Checks = append(result.Checks, Check{
			Name:   "VirusTotal",
			Status: Skip,
			Detail: "VT API rate limit hit — retry later or upgrade plan",
		})
		return result
	}

	var vtResp struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&vtResp); err != nil {
		result.Checks = append(result.Checks, Check{
			Name:   "VirusTotal",
			Status: Skip,
			Detail: "Failed to decode API response",
		})
		return result
	}

	stats := vtResp.Data.Attributes.LastAnalysisStats
	result.Malicious = stats.Malicious
	result.Suspicious = stats.Suspicious
	result.Harmless = stats.Harmless
	result.Undetected = stats.Undetected

	detail := fmt.Sprintf("Malicious: %d  Suspicious: %d  Harmless: %d  Undetected: %d",
		stats.Malicious, stats.Suspicious, stats.Harmless, stats.Undetected)

	var pts int
	var status Status
	switch {
	case stats.Malicious > 3:
		pts, status = 0, Fail
	case stats.Malicious > 0 || stats.Suspicious > 2:
		pts, status = 3, Warn
	case stats.Suspicious > 0:
		pts, status = 7, Warn
	default:
		pts, status = 10, Pass
	}

	result.Score = pts
	result.Checks = append(result.Checks, Check{
		Name:      "VirusTotal",
		Status:    status,
		Detail:    detail,
		Points:    pts,
		MaxPoints: 10,
	})

	return result
}
