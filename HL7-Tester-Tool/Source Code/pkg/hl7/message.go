// Package hl7 provides HL7 v2.x message parsing, building, and MLLP framing.
package hl7

import (
	"fmt"
	"strings"
	"time"
)

// MLLP framing bytes (Minimal Lower Layer Protocol)
const (
	MLLPStartBlock  = 0x0B // Vertical Tab
	MLLPEndBlock    = 0x1C // File Separator
	MLLPCarriageRet = 0x0D // Carriage Return
)

// Segment represents a single HL7 segment (e.g. MSH, PID, PV1)
type Segment struct {
	ID     string
	Fields []string
}

// Message represents a parsed HL7 v2.x message
type Message struct {
	Raw      string
	Segments []*Segment

	FieldSep    byte
	CompSep     byte
	RepeatSep   byte
	EscapeChar  byte
	SubcompSep  byte
	MessageType string
	MessageID   string
	Timestamp   time.Time
}

// Parse parses a raw HL7 message string into a Message struct.
// Handles both \r and \n segment delimiters.
func Parse(raw string) (*Message, error) {
	// Normalize line endings
	raw = strings.ReplaceAll(raw, "\r\n", "\r")
	raw = strings.ReplaceAll(raw, "\n", "\r")
	raw = strings.TrimSpace(raw)

	if len(raw) < 8 {
		return nil, fmt.Errorf("message too short to be valid HL7")
	}
	if !strings.HasPrefix(raw, "MSH") {
		return nil, fmt.Errorf("message does not begin with MSH segment")
	}

	msg := &Message{Raw: raw}

	// Parse encoding characters from MSH
	msg.FieldSep = raw[3]
	if len(raw) > 4 {
		msg.CompSep = raw[4]
	}
	if len(raw) > 5 {
		msg.RepeatSep = raw[5]
	}
	if len(raw) > 6 {
		msg.EscapeChar = raw[6]
	}
	if len(raw) > 7 {
		msg.SubcompSep = raw[7]
	}

	fieldSep := string(msg.FieldSep)
	lines := strings.Split(raw, "\r")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, fieldSep)
		seg := &Segment{
			ID:     fields[0],
			Fields: fields,
		}
		msg.Segments = append(msg.Segments, seg)
	}

	// Extract key MSH fields
	msh := msg.GetSegment("MSH")
	if msh != nil {
		if len(msh.Fields) > 9 {
			msg.MessageType = msh.Fields[9]
		}
		if len(msh.Fields) > 10 {
			msg.MessageID = msh.Fields[10]
		}
		if len(msh.Fields) > 7 {
			ts := msh.Fields[7]
			if len(ts) >= 14 {
				t, err := time.Parse("20060102150405", ts[:14])
				if err == nil {
					msg.Timestamp = t
				}
			} else if len(ts) >= 8 {
				t, err := time.Parse("20060102", ts[:8])
				if err == nil {
					msg.Timestamp = t
				}
			}
		}
	}

	return msg, nil
}

// GetSegment returns the first segment with the given ID, or nil.
func (m *Message) GetSegment(id string) *Segment {
	for _, s := range m.Segments {
		if s.ID == id {
			return s
		}
	}
	return nil
}

// GetAllSegments returns all segments with the given ID.
func (m *Message) GetAllSegments(id string) []*Segment {
	var result []*Segment
	for _, s := range m.Segments {
		if s.ID == id {
			result = append(result, s)
		}
	}
	return result
}

// Field safely returns a field value by 1-based index (MSH field numbers are 1-based).
func (s *Segment) Field(index int) string {
	if index < len(s.Fields) {
		return s.Fields[index]
	}
	return ""
}

// WrapMLLP wraps a raw HL7 message in MLLP framing for TCP transport.
// Per HL7 MLLP spec: 0x0B <message> 0x1C 0x0D
// Each segment must be separated by \r. The message must end with \r
// before the end-block byte or some receivers will reject it.
func WrapMLLP(msg string) []byte {
	// Normalize line endings to \r (HL7 segment separator)
	msg = strings.ReplaceAll(msg, "\r\n", "\r")
	msg = strings.ReplaceAll(msg, "\n", "\r")

	// Ensure exactly one trailing \r before end-block
	msg = strings.TrimRight(msg, "\r\n\t ")
	msg += "\r"

	frame := make([]byte, 0, len(msg)+3)
	frame = append(frame, MLLPStartBlock)  // 0x0B
	frame = append(frame, []byte(msg)...)  // HL7 content with \r segment separators
	frame = append(frame, MLLPEndBlock)    // 0x1C
	frame = append(frame, MLLPCarriageRet) // 0x0D
	return frame
}

// UnwrapMLLP strips MLLP framing from received bytes.
// Returns the raw HL7 content and whether framing was valid.
func UnwrapMLLP(data []byte) (string, bool) {
	if len(data) < 3 {
		return "", false
	}
	start := -1
	end := -1
	for i, b := range data {
		if b == MLLPStartBlock && start == -1 {
			start = i
		}
		if b == MLLPEndBlock && start != -1 {
			end = i
			break
		}
	}
	if start == -1 || end == -1 || end <= start {
		return string(data), false // return raw, mark as unframed
	}
	return string(data[start+1 : end]), true
}

// BuildACK constructs an ACK response for the given message.
// ackCode: "AA" (accept), "AE" (error), "AR" (reject)
func BuildACK(original *Message, ackCode string, errMsg string) string {
	now := time.Now().Format("20060102150405")
	msgID := fmt.Sprintf("ACK%d", time.Now().UnixMilli())

	// Extract original MSH fields for the ACK
	origMSH := original.GetSegment("MSH")
	sendingApp := ""
	sendingFac := ""
	receivingApp := ""
	receivingFac := ""
	if origMSH != nil {
		sendingApp = origMSH.Field(3)
		sendingFac = origMSH.Field(4)
		receivingApp = origMSH.Field(5)
		receivingFac = origMSH.Field(6)
	}

	msh := fmt.Sprintf("MSH|^~\\&|%s|%s|%s|%s|%s||ACK|%s|P|2.5",
		receivingApp, receivingFac, sendingApp, sendingFac, now, msgID)
	msa := fmt.Sprintf("MSA|%s|%s|%s", ackCode, original.MessageID, errMsg)

	return msh + "\r" + msa + "\r"
}

// SummaryString returns a human-readable one-line summary of the message.
func (m *Message) SummaryString() string {
	pid := m.GetSegment("PID")
	patientName := "<no PID>"
	if pid != nil && len(pid.Fields) > 5 {
		patientName = pid.Fields[5]
	}
	return fmt.Sprintf("Type=%-12s ID=%-20s Patient=%-30s Segments=%d",
		m.MessageType, m.MessageID, patientName, len(m.Segments))
}

// ContainsPHI does a basic scan for obvious PHI fields in the message.
// Returns field paths that appear to contain patient data.
func (m *Message) ContainsPHI() []string {
	var found []string
	phiSegments := map[string][]int{
		"PID": {3, 5, 6, 7, 8, 11, 13, 14, 19}, // Patient ID, Name, DOB, SSN, Address, Phone
		"NK1": {2, 4, 5},                         // Next of kin name, address, phone
		"GT1": {3, 4, 5},                         // Guarantor name, address, phone
		"IN1": {16, 17},                           // Insured name, address
	}
	for segID, fieldIdxs := range phiSegments {
		seg := m.GetSegment(segID)
		if seg == nil {
			continue
		}
		for _, idx := range fieldIdxs {
			val := seg.Field(idx)
			if val != "" && val != "\"\"" {
				found = append(found, fmt.Sprintf("%s-%d=%q", segID, idx, truncate(val, 20)))
			}
		}
	}
	return found
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
