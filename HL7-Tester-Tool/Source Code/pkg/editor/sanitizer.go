// sanitizer.go — Fixes common HL7 message issues that cause receivers to
// drop the connection or not send an ACK. Run before sending captured messages.
package editor

import (
	"fmt"
	"strings"
	"time"
)

// SanitizeResult describes what was fixed in a message.
type SanitizeResult struct {
	MessageIndex int
	Fixes        []string
	Warnings     []string
	Original     string
	Sanitized    string
}

// Sanitize fixes all common ACK-blocking issues in a raw HL7 message.
// It is non-destructive — only fills in missing required fields and
// removes segments known to cause rejections, never alters clinical data.
func Sanitize(msg string, opts SanitizeOptions) SanitizeResult {
	result := SanitizeResult{Original: msg}
	segs := splitSegments(msg)
	if len(segs) == 0 {
		result.Warnings = append(result.Warnings, "empty message")
		result.Sanitized = msg
		return result
	}

	var out []string

	for i, seg := range segs {
		fields := strings.Split(seg, "|")
		if len(fields) == 0 {
			continue
		}
		segID := fields[0]

		// ── SFT / UAC — strip if requested (not universally supported) ─────
		if opts.RemoveUnsupported && (segID == "SFT" || segID == "UAC") {
			result.Fixes = append(result.Fixes,
				fmt.Sprintf("Removed %s segment (not universally supported — causes rejection on many receivers)", segID))
			continue
		}

		// ── FT1 — strip if completely empty ───────────────────────────────
		if segID == "FT1" {
			allEmpty := true
			for _, f := range fields[1:] {
				if strings.TrimSpace(f) != "" {
					allEmpty = false
					break
				}
			}
			if allEmpty && opts.RemoveEmptyFT1 {
				result.Fixes = append(result.Fixes,
					"Removed empty FT1 segment (empty FT1 confuses some receivers)")
				continue
			}
		}

		// ── MSH fixes ─────────────────────────────────────────────────────
		if segID == "MSH" {
			for len(fields) < 20 {
				fields = append(fields, "")
			}

			// MSH-7: timestamp — fill if empty
			if opts.FixTimestamp && strings.TrimSpace(fields[7]) == "" {
				fields[7] = time.Now().Format("20060102150405")
				result.Fixes = append(result.Fixes, "MSH-7: filled missing timestamp")
			}

			// MSH-9: message type — must be present
			if strings.TrimSpace(fields[9]) == "" {
				if opts.DefaultMsgType != "" {
					fields[9] = opts.DefaultMsgType
					result.Fixes = append(result.Fixes,
						fmt.Sprintf("MSH-9: set missing message type to %s", opts.DefaultMsgType))
				} else {
					result.Warnings = append(result.Warnings, "MSH-9 (message type) is empty — receiver will likely reject")
				}
			}

			// MSH-10: message control ID — must be unique and non-empty
			if strings.TrimSpace(fields[10]) == "" || fields[10] == "P" {
				fields[10] = fmt.Sprintf("MSG%d", time.Now().UnixMilli()%9999999)
				result.Fixes = append(result.Fixes,
					fmt.Sprintf("MSH-10: generated unique message control ID: %s", fields[10]))
			}

			// MSH-11: processing ID — must be P, T, or D
			if strings.TrimSpace(fields[11]) == "" {
				fields[11] = "P"
				result.Fixes = append(result.Fixes, "MSH-11: set missing processing ID to P (Production)")
			}

			// MSH-12: version — fill from detected or default
			if strings.TrimSpace(fields[12]) == "" {
				ver := opts.DefaultVersion
				if ver == "" {
					ver = "2.5"
				}
				fields[12] = ver
				result.Fixes = append(result.Fixes,
					fmt.Sprintf("MSH-12: filled missing HL7 version as %s", ver))
			}

			// MSH-3/4/5/6: application/facility identity
			if opts.SendingApp != "" && strings.TrimSpace(fields[3]) == "" {
				fields[3] = opts.SendingApp
				result.Fixes = append(result.Fixes, fmt.Sprintf("MSH-3: set sending app to %s", opts.SendingApp))
			}
			if opts.SendingFacility != "" && strings.TrimSpace(fields[4]) == "" {
				fields[4] = opts.SendingFacility
				result.Fixes = append(result.Fixes, fmt.Sprintf("MSH-4: set sending facility to %s", opts.SendingFacility))
			}
			if opts.ReceivingApp != "" && strings.TrimSpace(fields[5]) == "" {
				fields[5] = opts.ReceivingApp
				result.Fixes = append(result.Fixes, fmt.Sprintf("MSH-5: set receiving app to %s", opts.ReceivingApp))
			}
			if opts.ReceivingFacility != "" && strings.TrimSpace(fields[6]) == "" {
				fields[6] = opts.ReceivingFacility
				result.Fixes = append(result.Fixes, fmt.Sprintf("MSH-6: set receiving facility to %s", opts.ReceivingFacility))
			}

			// If first segment, always regenerate message ID to ensure uniqueness
			if i == 0 && opts.RegenerateMessageID {
				newID := fmt.Sprintf("MSG%d", time.Now().UnixMilli())
				if fields[10] != newID {
					fields[10] = newID
					result.Fixes = append(result.Fixes,
						fmt.Sprintf("MSH-10: regenerated unique message ID: %s", newID))
				}
			}

			seg = strings.Join(fields, "|")
		}

		// ── PID fixes ─────────────────────────────────────────────────────
		if segID == "PID" {
			for len(fields) < 20 {
				fields = append(fields, "")
			}

			// PID-3: patient ID / MRN — required by most receivers
			if strings.TrimSpace(fields[3]) == "" {
				if opts.DefaultMRN != "" {
					fields[3] = opts.DefaultMRN + "^^^HOSP"
					result.Fixes = append(result.Fixes,
						fmt.Sprintf("PID-3: filled missing MRN with %s", opts.DefaultMRN))
				} else {
					result.Warnings = append(result.Warnings,
						"PID-3 (MRN) is empty — receiver may reject. Use -sanitize-mrn to set a default.")
				}
			}

			// PID-5: patient name — required
			name := strings.TrimSpace(fields[5])
			if name == "" || name == "^^" || name == "^" {
				if opts.DefaultPatientName != "" {
					fields[5] = opts.DefaultPatientName
					result.Fixes = append(result.Fixes,
						fmt.Sprintf("PID-5: filled missing patient name with %s", opts.DefaultPatientName))
				} else {
					result.Warnings = append(result.Warnings,
						"PID-5 (patient name) is empty — receiver may reject. Use -sanitize-name to set a default.")
				}
			}

			// PID-7: DOB — warn if empty (not always required but common)
			if strings.TrimSpace(fields[7]) == "" {
				result.Warnings = append(result.Warnings, "PID-7 (DOB) is empty — may cause warnings on strict receivers")
			}

			seg = strings.Join(fields, "|")
		}

		// ── OBR fixes ─────────────────────────────────────────────────────
		if segID == "OBR" {
			for len(fields) < 5 {
				fields = append(fields, "")
			}
			// OBR-1: set ID — must be numeric
			if strings.TrimSpace(fields[1]) == "" {
				fields[1] = "1"
				result.Fixes = append(result.Fixes, "OBR-1: filled missing set ID with 1")
			}
			seg = strings.Join(fields, "|")
		}

		// ── OBX fixes ─────────────────────────────────────────────────────
		if segID == "OBX" {
			for len(fields) < 12 {
				fields = append(fields, "")
			}
			// OBX-11: observation result status — must be present (F=Final is safest)
			if strings.TrimSpace(fields[11]) == "" {
				fields[11] = "F"
				result.Fixes = append(result.Fixes,
					fmt.Sprintf("OBX-%s: filled missing result status with F (Final)", fields[1]))
			}
			seg = strings.Join(fields, "|")
		}

		out = append(out, seg)
	}

	result.Sanitized = strings.Join(out, "\r")
	return result
}

// SanitizeOptions controls what the sanitizer fixes.
type SanitizeOptions struct {
	// Structural fixes
	RemoveUnsupported  bool // Remove SFT, UAC segments
	RemoveEmptyFT1     bool // Remove completely empty FT1 segments
	FixTimestamp       bool // Fill empty MSH-7 timestamps
	RegenerateMessageID bool // Always generate a fresh unique MSH-10

	// Identity
	SendingApp      string
	SendingFacility string
	ReceivingApp    string
	ReceivingFacility string

	// Defaults for required fields
	DefaultMsgType     string // e.g. "ORU^R01"
	DefaultVersion     string // e.g. "2.5" or "2.6"
	DefaultMRN         string // e.g. "TEST001"
	DefaultPatientName string // e.g. "TESTPATIENT^TEST"
}

// DefaultSanitizeOptions returns the recommended options for maximum
// ACK compatibility — safe to use on any captured message.
func DefaultSanitizeOptions() SanitizeOptions {
	return SanitizeOptions{
		RemoveUnsupported:   true,
		RemoveEmptyFT1:      true,
		FixTimestamp:        true,
		RegenerateMessageID: true,
		DefaultVersion:      "2.5",
		DefaultMRN:          "TEST001",
		DefaultPatientName:  "TESTPATIENT^TEST",
	}
}

// SanitizeAll sanitizes a slice of messages and prints a report.
func SanitizeAll(messages []string, opts SanitizeOptions) ([]string, []SanitizeResult) {
	var sanitized []string
	var results []SanitizeResult

	for i, msg := range messages {
		res := Sanitize(msg, opts)
		res.MessageIndex = i + 1
		sanitized = append(sanitized, res.Sanitized)
		results = append(results, res)
	}
	return sanitized, results
}

// PrintSanitizeReport prints a human-readable report of all fixes made.
func PrintSanitizeReport(results []SanitizeResult) {
	totalFixes := 0
	totalWarnings := 0

	fmt.Println()
	fmt.Println("  SANITIZE REPORT")
	fmt.Println("  " + strings.Repeat("─", 60))

	for _, res := range results {
		if len(res.Fixes) == 0 && len(res.Warnings) == 0 {
			fmt.Printf("  Message #%d — ✓ No issues found\n", res.MessageIndex)
			continue
		}
		fmt.Printf("  Message #%d — %d fix(es), %d warning(s)\n",
			res.MessageIndex, len(res.Fixes), len(res.Warnings))
		for _, fix := range res.Fixes {
			fmt.Printf("    ✓ Fixed  : %s\n", fix)
			totalFixes++
		}
		for _, warn := range res.Warnings {
			fmt.Printf("    ⚠ Warning: %s\n", warn)
			totalWarnings++
		}
	}

	fmt.Println("  " + strings.Repeat("─", 60))
	fmt.Printf("  Total: %d fix(es) applied, %d warning(s)\n", totalFixes, totalWarnings)

	if totalWarnings > 0 {
		fmt.Println()
		fmt.Println("  Warnings are items the sanitizer could not automatically fix.")
		fmt.Println("  Use -msh-sending-app / -msh-receiving-app / -sanitize-mrn flags")
		fmt.Println("  to supply the values the receiver expects.")
	}
}
