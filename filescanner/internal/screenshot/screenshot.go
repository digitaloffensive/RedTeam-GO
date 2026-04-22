// Package screenshot captures a text "screenshot" of matched file content
// and encodes it as a base64 PNG-like text block embedded in the CSV.
// On headless/server environments we render an ASCII art image of the
// flagged lines and base64-encode the result so it survives CSV quoting.
package screenshot

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
)

const (
	maxPreviewLines = 20
	maxLineWidth    = 120
)

// Capture builds a text "screenshot" image of the flagged file content.
// matchedLines is a map of lineNumber -> lineContent.
// Returns a base64-encoded text block suitable for embedding in CSV.
func Capture(filePath string, allLines []string, matchedLineNums []int) string {
	if len(matchedLineNums) == 0 {
		return ""
	}

	// Build a set for quick lookup
	matchSet := make(map[int]struct{}, len(matchedLineNums))
	for _, n := range matchedLineNums {
		matchSet[n] = struct{}{}
	}

	var buf bytes.Buffer
	header := fmt.Sprintf("FILE: %s", filePath)
	buf.WriteString(strings.Repeat("=", min(len(header)+4, maxLineWidth)) + "\n")
	buf.WriteString("| " + header + " |\n")
	buf.WriteString(strings.Repeat("=", min(len(header)+4, maxLineWidth)) + "\n")

	shown := 0
	for _, lineNum := range matchedLineNums {
		if shown >= maxPreviewLines {
			buf.WriteString(fmt.Sprintf("... (%d more matched lines omitted)\n", len(matchedLineNums)-shown))
			break
		}
		// Show 2 lines of context before and after
		start := max(0, lineNum-3)
		end := min(len(allLines)-1, lineNum+2)

		for i := start; i <= end; i++ {
			line := allLines[i]
			if len(line) > maxLineWidth {
				line = line[:maxLineWidth] + "…"
			}
			// Redact values after assignment operators to avoid storing real secrets
			line = redactSensitive(line)
			prefix := "    "
			if _, hit := matchSet[i+1]; hit {
				prefix = ">>> " // highlight matched line
			}
			buf.WriteString(fmt.Sprintf("%s%4d | %s\n", prefix, i+1, line))
		}
		buf.WriteString("\n")
		shown++
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// redactSensitive partially redacts values that look like secrets.
func redactSensitive(line string) string {
	// Replace anything after = or : that looks like a credential value
	// with a partial redaction: show first 3 chars, then asterisks.
	result := line
	for _, sep := range []string{"=", ":"} {
		idx := strings.Index(result, sep)
		if idx != -1 && idx < len(result)-4 {
			val := strings.TrimSpace(result[idx+1:])
			// Strip quotes
			val = strings.Trim(val, `"'`)
			if len(val) > 6 {
				redacted := val[:3] + strings.Repeat("*", min(len(val)-3, 8))
				result = result[:idx+1] + " " + redacted
				break
			}
		}
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Decode reverses a Capture result for display purposes.
func Decode(encoded string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
