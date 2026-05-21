// pcap.go — Extracts HL7 messages from network packet capture files (.pcap / .pcapng).
// Reads raw TCP streams and pulls out any MLLP-framed or bare HL7 content.
// Useful when you have a network capture from a span port or Wireshark session
// and want to extract the real messages for use in security testing — without
// needing to connect to the receiver at all.
//
// Does NOT require libpcap or any C dependencies — reads pcap binary format directly.
package pcap

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Result types
// ─────────────────────────────────────────────────────────────────────────────

// ExtractedMessage is a single HL7 message found in a capture file.
type ExtractedMessage struct {
	Index      int
	Timestamp  time.Time
	SrcIP      string
	SrcPort    uint16
	DstIP      string
	DstPort    uint16
	Raw        string
	MLLPFramed bool
	MsgType    string
	MsgID      string
	SendingApp string
	PatientMRN string
	PHIFields  []string
}

// CaptureReport summarises what was found in a pcap file.
type CaptureReport struct {
	File           string
	TotalPackets   int
	HL7Packets     int
	MessagesFound  int
	UniqueEndpoints []string
	Messages       []*ExtractedMessage
	Flows          []FlowSummary
}

// FlowSummary describes a single HL7 communication flow between two endpoints.
type FlowSummary struct {
	Src      string
	Dst      string
	MsgCount int
	MsgTypes []string
}

// ─────────────────────────────────────────────────────────────────────────────
// PCAP file parser (pure Go — no libpcap dependency)
// ─────────────────────────────────────────────────────────────────────────────

const (
	pcapMagicLE       = 0xa1b2c3d4 // little-endian pcap
	pcapMagicBE       = 0xd4c3b2a1 // big-endian pcap
	pcapNGMagic       = 0x0a0d0d0a // pcapng
	linkTypeEthernet  = 1
	linkTypeRaw       = 101
	linkTypeLoopback  = 0
	mllpStart         = 0x0B
	mllpEnd           = 0x1C
)

// ExtractFromFile reads a .pcap or .pcapng file and returns all HL7 messages found.
func ExtractFromFile(path string) (*CaptureReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open capture file: %w", err)
	}
	defer f.Close()

	// Peek at magic bytes to determine format
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return nil, fmt.Errorf("cannot read file header: %w", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}

	magicVal := binary.BigEndian.Uint32(magic[:])
	switch magicVal {
	case pcapMagicLE, pcapMagicBE:
		return parsePcap(f, path)
	case pcapNGMagic:
		return parsePcapNG(f, path)
	default:
		// Try little-endian interpretation
		magicValLE := binary.LittleEndian.Uint32(magic[:])
		if magicValLE == pcapMagicLE {
			return parsePcap(f, path)
		}
		return nil, fmt.Errorf("unrecognised file format (magic: %08x) — expected .pcap or .pcapng", magicVal)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy .pcap parser
// ─────────────────────────────────────────────────────────────────────────────

func parsePcap(r io.Reader, path string) (*CaptureReport, error) {
	report := &CaptureReport{File: path}

	// Global header: magic(4) + version_major(2) + version_minor(2) + thiszone(4)
	//                + sigfigs(4) + snaplen(4) + network(4) = 24 bytes
	var hdr [24]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("truncated pcap header")
	}

	// Determine byte order from magic
	var bo binary.ByteOrder = binary.LittleEndian
	magic := binary.LittleEndian.Uint32(hdr[0:4])
	if magic == pcapMagicBE {
		bo = binary.BigEndian
	}

	linkType := bo.Uint32(hdr[20:24])

	// TCP stream reassembly buffers: key = "srcIP:srcPort->dstIP:dstPort"
	streams := make(map[string][]byte)

	var messages []*ExtractedMessage
	msgIdx := 1

	for {
		// Packet record header: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4)
		var recHdr [16]byte
		if _, err := io.ReadFull(r, recHdr[:]); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("truncated packet record: %w", err)
		}
		tsSec := bo.Uint32(recHdr[0:4])
		tsUsec := bo.Uint32(recHdr[4:8])
		inclLen := bo.Uint32(recHdr[8:12])

		pktData := make([]byte, inclLen)
		if _, err := io.ReadFull(r, pktData); err != nil {
			break
		}
		report.TotalPackets++

		ts := time.Unix(int64(tsSec), int64(tsUsec)*1000)
		srcIP, srcPort, dstIP, dstPort, payload := extractTCPPayload(pktData, linkType)
		if len(payload) == 0 {
			continue
		}

		// Does this payload contain anything HL7-like?
		if !looksLikeHL7(payload) {
			continue
		}
		report.HL7Packets++

		key := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
		streams[key] = append(streams[key], payload...)

		// Try to extract complete messages from the stream buffer
		extracted, remainder := extractHL7FromBuffer(streams[key])
		streams[key] = remainder

		for _, raw := range extracted {
			msg := parseExtractedMessage(raw, msgIdx, ts, srcIP, dstIP, srcPort, dstPort)
			messages = append(messages, msg)
			msgIdx++
		}
	}

	// Drain any remaining stream buffers that might have incomplete messages
	for key, buf := range streams {
		if len(buf) > 10 && looksLikeHL7(buf) {
			parts := strings.SplitN(key, "->", 2)
			srcPart, dstPart := "", ""
			if len(parts) == 2 {
				srcPart = parts[0]
				dstPart = parts[1]
			}
			sip, sport := splitEndpoint(srcPart)
			dip, dport := splitEndpoint(dstPart)
			msg := parseExtractedMessage(string(buf), msgIdx, time.Now(), sip, sport, dip, dport)
			msg.MLLPFramed = false
			messages = append(messages, msg)
			msgIdx++
		}
	}

	report.Messages = messages
	report.MessagesFound = len(messages)
	report.UniqueEndpoints = collectEndpoints(messages)
	report.Flows = buildFlows(messages)
	return report, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// pcapng parser (simplified — extracts Enhanced Packet Blocks)
// ─────────────────────────────────────────────────────────────────────────────

func parsePcapNG(r io.Reader, path string) (*CaptureReport, error) {
	report := &CaptureReport{File: path}
	streams := make(map[string][]byte)
	var messages []*ExtractedMessage
	msgIdx := 1
	linkType := uint32(linkTypeEthernet)

	for {
		// Block type + block total length
		var blockHdr [8]byte
		if _, err := io.ReadFull(r, blockHdr[:]); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("truncated pcapng block header")
		}

		blockType := binary.LittleEndian.Uint32(blockHdr[0:4])
		blockLen := binary.LittleEndian.Uint32(blockHdr[4:8])

		if blockLen < 12 {
			break
		}

		bodyLen := int(blockLen) - 12 // subtract type(4) + len(4) + trailing len(4)
		if bodyLen < 0 {
			break
		}
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(r, body); err != nil {
			break
		}
		// Trailing block total length
		var trailingLen [4]byte
		io.ReadFull(r, trailingLen[:]) //nolint:errcheck

		switch blockType {
		case 0x00000001: // Interface Description Block
			if len(body) >= 4 {
				linkType = binary.LittleEndian.Uint32(body[0:4]) & 0xFFFF
			}

		case 0x00000006: // Enhanced Packet Block
			if len(body) < 20 {
				continue
			}
			tsSec := binary.LittleEndian.Uint32(body[4:8])
			tsUsec := binary.LittleEndian.Uint32(body[8:12])
			capturedLen := binary.LittleEndian.Uint32(body[12:16])
			if capturedLen > uint32(len(body)-20) {
				capturedLen = uint32(len(body) - 20)
			}
			pktData := body[20 : 20+capturedLen]
			report.TotalPackets++
			ts := time.Unix(int64(tsSec), int64(tsUsec)*1000)

			srcIP, srcPort, dstIP, dstPort, payload := extractTCPPayload(pktData, linkType)
			if len(payload) == 0 || !looksLikeHL7(payload) {
				continue
			}
			report.HL7Packets++

			key := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
			streams[key] = append(streams[key], payload...)
			extracted, remainder := extractHL7FromBuffer(streams[key])
			streams[key] = remainder

			for _, raw := range extracted {
				msg := parseExtractedMessage(raw, msgIdx, ts, srcIP, dstIP, srcPort, dstPort)
				messages = append(messages, msg)
				msgIdx++
			}
		}
	}

	report.Messages = messages
	report.MessagesFound = len(messages)
	report.UniqueEndpoints = collectEndpoints(messages)
	report.Flows = buildFlows(messages)
	return report, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Packet dissection
// ─────────────────────────────────────────────────────────────────────────────

// extractTCPPayload dissects an Ethernet/IP/TCP stack and returns the TCP payload.
// Returns empty payload if the packet is not TCP or has no application data.
func extractTCPPayload(pkt []byte, linkType uint32) (srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) {
	pos := 0

	// Strip link-layer header
	switch linkType {
	case linkTypeEthernet:
		if len(pkt) < 14 {
			return
		}
		etherType := binary.BigEndian.Uint16(pkt[12:14])
		pos = 14
		// Handle 802.1Q VLAN tag
		if etherType == 0x8100 {
			if len(pkt) < 18 {
				return
			}
			etherType = binary.BigEndian.Uint16(pkt[16:18])
			pos = 18
		}
		if etherType != 0x0800 && etherType != 0x86DD {
			return // not IPv4 or IPv6
		}
	case linkTypeLoopback:
		if len(pkt) < 4 {
			return
		}
		pos = 4
	case linkTypeRaw:
		pos = 0
	default:
		if len(pkt) >= 14 {
			pos = 14 // assume Ethernet
		}
	}

	if pos >= len(pkt) {
		return
	}
	ipData := pkt[pos:]

	// IPv4
	if len(ipData) < 20 {
		return
	}
	version := (ipData[0] >> 4) & 0xF
	if version != 4 {
		return // skip IPv6 for now
	}
	if ipData[9] != 6 { // protocol != TCP
		return
	}
	ihl := int(ipData[0]&0xF) * 4
	if ihl < 20 || ihl >= len(ipData) {
		return
	}
	srcIP = fmt.Sprintf("%d.%d.%d.%d", ipData[12], ipData[13], ipData[14], ipData[15])
	dstIP = fmt.Sprintf("%d.%d.%d.%d", ipData[16], ipData[17], ipData[18], ipData[19])
	tcpData := ipData[ihl:]

	// TCP header
	if len(tcpData) < 20 {
		return
	}
	srcPort = binary.BigEndian.Uint16(tcpData[0:2])
	dstPort = binary.BigEndian.Uint16(tcpData[2:4])
	tcpHdrLen := int((tcpData[12]>>4)&0xF) * 4
	if tcpHdrLen < 20 || tcpHdrLen >= len(tcpData) {
		return
	}
	payload = tcpData[tcpHdrLen:]
	return
}

// ─────────────────────────────────────────────────────────────────────────────
// HL7 extraction from TCP stream buffer
// ─────────────────────────────────────────────────────────────────────────────

// looksLikeHL7 does a quick check before expensive processing.
func looksLikeHL7(data []byte) bool {
	s := string(data)
	// MLLP framed
	if len(data) > 4 && data[0] == mllpStart {
		return true
	}
	// Bare HL7 — starts with MSH
	if strings.Contains(s, "MSH|") {
		return true
	}
	// Inside a stream buffer that accumulated partial data
	if strings.Contains(s, "\rMSH|") || strings.Contains(s, "\nMSH|") {
		return true
	}
	return false
}

// extractHL7FromBuffer pulls complete HL7 messages from a TCP stream buffer.
// Returns the extracted messages and any remaining incomplete data.
func extractHL7FromBuffer(buf []byte) (messages []string, remainder []byte) {
	s := string(buf)
	s = strings.ReplaceAll(s, "\r\n", "\r")
	s = strings.ReplaceAll(s, "\n", "\r")

	pos := 0

	for pos < len(s) {
		// Try MLLP framing first
		startIdx := strings.IndexByte(s[pos:], mllpStart)
		if startIdx >= 0 {
			start := pos + startIdx
			endIdx := strings.IndexByte(s[start+1:], mllpEnd)
			if endIdx < 0 {
				// Incomplete MLLP frame — keep in buffer
				remainder = []byte(s[start:])
				return
			}
			end := start + 1 + endIdx
			msg := s[start+1 : end]
			msg = strings.Trim(msg, "\r\t ")
			if strings.Contains(msg, "MSH|") {
				messages = append(messages, msg)
			}
			pos = end + 2 // skip 0x1C and 0x0D
			continue
		}

		// No MLLP framing — look for bare MSH
		mshIdx := strings.Index(s[pos:], "MSH|")
		if mshIdx < 0 {
			break
		}
		mshStart := pos + mshIdx

		// Find the end of this message — next MSH or end of buffer
		nextMSH := strings.Index(s[mshStart+4:], "MSH|")
		var msg string
		if nextMSH < 0 {
			// Only one message, may be incomplete — keep for next packet
			remainder = []byte(s[mshStart:])
			return
		}
		msgEnd := mshStart + 4 + nextMSH
		msg = strings.Trim(s[mshStart:msgEnd], "\r\t ")
		if len(msg) > 20 {
			messages = append(messages, msg)
		}
		pos = msgEnd
	}
	return
}

// ─────────────────────────────────────────────────────────────────────────────
// Message parsing
// ─────────────────────────────────────────────────────────────────────────────

func parseExtractedMessage(raw string, idx int, ts time.Time, srcIP string, srcPort uint16, dstIP string, dstPort uint16) *ExtractedMessage {
	msg := &ExtractedMessage{
		Index:     idx,
		Timestamp: ts,
		SrcIP:     srcIP,
		SrcPort:   srcPort,
		DstIP:     dstIP,
		DstPort:   dstPort,
		Raw:       raw,
	}

	// Detect MLLP framing
	msg.MLLPFramed = len(raw) > 0 && (raw[0] == mllpStart || strings.HasPrefix(strings.TrimSpace(raw), string([]byte{mllpStart})))

	// Parse key MSH fields
	for _, line := range strings.Split(raw, "\r") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, "|")
		switch {
		case fields[0] == "MSH":
			if len(fields) > 3 {
				msg.SendingApp = fields[3]
			}
			if len(fields) > 9 {
				msg.MsgType = fields[9]
			}
			if len(fields) > 10 {
				msg.MsgID = fields[10]
			}
		case fields[0] == "PID":
			if len(fields) > 3 {
				msg.PatientMRN = fields[3]
			}
			// Collect all non-empty PID fields as potential PHI
			phiFieldNames := map[int]string{
				3: "MRN", 5: "Name", 7: "DOB", 8: "Sex",
				11: "Address", 13: "Phone", 19: "SSN",
			}
			for idx, name := range phiFieldNames {
				if idx < len(fields) && strings.TrimSpace(fields[idx]) != "" && fields[idx] != `""` {
					msg.PHIFields = append(msg.PHIFields, fmt.Sprintf("%s=%s", name, truncate(fields[idx], 30)))
				}
			}
		}
	}
	return msg
}

// ─────────────────────────────────────────────────────────────────────────────
// Report building
// ─────────────────────────────────────────────────────────────────────────────

func collectEndpoints(messages []*ExtractedMessage) []string {
	seen := map[string]bool{}
	for _, m := range messages {
		seen[fmt.Sprintf("%s:%d", m.SrcIP, m.SrcPort)] = true
		seen[fmt.Sprintf("%s:%d", m.DstIP, m.DstPort)] = true
	}
	var eps []string
	for ep := range seen {
		eps = append(eps, ep)
	}
	sort.Strings(eps)
	return eps
}

func buildFlows(messages []*ExtractedMessage) []FlowSummary {
	type flowKey struct{ src, dst string }
	flows := map[flowKey]*FlowSummary{}
	typesSeen := map[flowKey]map[string]bool{}

	for _, m := range messages {
		src := fmt.Sprintf("%s:%d", m.SrcIP, m.SrcPort)
		dst := fmt.Sprintf("%s:%d", m.DstIP, m.DstPort)
		k := flowKey{src, dst}
		if flows[k] == nil {
			flows[k] = &FlowSummary{Src: src, Dst: dst}
			typesSeen[k] = map[string]bool{}
		}
		flows[k].MsgCount++
		if m.MsgType != "" {
			typesSeen[k][m.MsgType] = true
		}
	}
	for k, f := range flows {
		for t := range typesSeen[k] {
			f.MsgTypes = append(f.MsgTypes, t)
		}
		sort.Strings(f.MsgTypes)
	}
	var result []FlowSummary
	for _, f := range flows {
		result = append(result, *f)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].MsgCount > result[j].MsgCount
	})
	return result
}

// ─────────────────────────────────────────────────────────────────────────────
// Report printing
// ─────────────────────────────────────────────────────────────────────────────

// PrintReport writes a human-readable summary to stdout.
func (r *CaptureReport) PrintReport() {
	sep := strings.Repeat("═", 70)
	thin := strings.Repeat("─", 70)

	fmt.Println()
	fmt.Println(sep)
	fmt.Println("  PCAP ANALYSIS REPORT — HL7 Message Extraction")
	fmt.Println(sep)
	fmt.Printf("  File           : %s\n", r.File)
	fmt.Printf("  Total packets  : %d\n", r.TotalPackets)
	fmt.Printf("  HL7 packets    : %d\n", r.HL7Packets)
	fmt.Printf("  Messages found : %d\n", r.MessagesFound)
	fmt.Println()

	if len(r.Flows) > 0 {
		fmt.Println("  Communication flows:")
		fmt.Println("  " + thin[:66])
		for _, f := range r.Flows {
			fmt.Printf("  %-28s → %-28s  %3d msg(s)  [%s]\n",
				f.Src, f.Dst, f.MsgCount, strings.Join(f.MsgTypes, ", "))
		}
		fmt.Println()
	}

	if len(r.UniqueEndpoints) > 0 {
		fmt.Printf("  Unique endpoints: %s\n", strings.Join(r.UniqueEndpoints, ", "))
		fmt.Println()
	}

	fmt.Println("  Extracted messages:")
	fmt.Println("  " + thin[:66])
	for _, m := range r.Messages {
		framed := "bare"
		if m.MLLPFramed {
			framed = "MLLP"
		}
		fmt.Printf("  [%03d] %s  %-14s %-22s  %s→%s:%d  %s\n",
			m.Index,
			m.Timestamp.Format("15:04:05.000"),
			m.MsgType,
			m.MsgID,
			m.SendingApp,
			m.DstIP, m.DstPort,
			framed,
		)
		if len(m.PHIFields) > 0 {
			fmt.Printf("        PHI: %s\n", strings.Join(m.PHIFields, ", "))
		}
	}
	fmt.Println(sep)
}

// SaveMessages writes all extracted messages to a .hl7 file suitable for
// loading directly into the security tester or editor.
func (r *CaptureReport) SaveMessages(path string) error {
	var sb strings.Builder
	for i, m := range r.Messages {
		// Write comment header for traceability
		sb.WriteString(fmt.Sprintf("# Message %d — %s %s→%s:%d  %s\n",
			m.Index, m.Timestamp.Format(time.RFC3339),
			m.SrcIP, m.DstIP, m.DstPort, m.MsgType))
		// Normalise to \n for file storage
		normalized := strings.ReplaceAll(m.Raw, "\r", "\n")
		sb.WriteString(normalized)
		if i < len(r.Messages)-1 {
			sb.WriteString("\n\n")
		}
	}
	sb.WriteString("\n")
	return os.WriteFile(path, []byte(sb.String()), 0644)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func splitEndpoint(ep string) (string, uint16) {
	idx := strings.LastIndex(ep, ":")
	if idx < 0 {
		return ep, 0
	}
	ip := ep[:idx]
	var port uint16
	fmt.Sscanf(ep[idx+1:], "%d", &port)
	return ip, port
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
