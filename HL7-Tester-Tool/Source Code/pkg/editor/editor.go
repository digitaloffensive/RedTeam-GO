// Package editor provides an interactive HL7 message editor.
// Supports adding segments, pasting real HL7 from live systems,
// editing individual fields, and saving back to file.
package editor

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hl7-security-tester/pkg/hl7"
)

// Editor holds the in-memory message list and the path of the file
// it was loaded from (used as the default save target).
type Editor struct {
	Messages []string
	FilePath string
	reader   *bufio.Reader
}

// New creates a new Editor pre-loaded with the given messages.
func New(filePath string, messages []string) *Editor {
	return &Editor{
		Messages: messages,
		FilePath: filePath,
		reader:   bufio.NewReader(os.Stdin),
	}
}

// Run launches the interactive editor shell.
func (e *Editor) Run() {
	fmt.Println()
	fmt.Println("  ┌─────────────────────────────────────────────────────────────┐")
	fmt.Println("  │              HL7 MESSAGE EDITOR                             │")
	fmt.Println("  │  Add segments, paste real HL7, edit fields, save to file    │")
	fmt.Println("  └─────────────────────────────────────────────────────────────┘")
	e.printHelp()

	for {
		fmt.Print("\n  editor> ")
		line, err := e.reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := strings.ToLower(parts[0])
		args := parts[1:]

		switch cmd {
		case "help", "?":
			e.printHelp()

		case "list", "ls":
			e.cmdList()

		case "show":
			e.cmdShow(args)

		case "new":
			e.cmdNew()

		case "paste":
			e.cmdPaste(args)

		case "add-seg", "add":
			e.cmdAddSegment(args)

		case "del-seg", "del":
			e.cmdDelSegment(args)

		case "edit-field", "edit":
			e.cmdEditField(args)

		case "set-field", "set":
			e.cmdSetField(args)

		case "del-msg":
			e.cmdDelMessage(args)

		case "dup", "copy":
			e.cmdDuplicate(args)

		case "save":
			e.cmdSave(args)

		case "import":
			e.cmdImport(args)

		case "export":
			e.cmdExport(args)

		case "validate":
			e.cmdValidate(args)

		case "sanitize", "fix":
			e.cmdSanitize(args)

		case "fuzz":
			e.cmdFuzz(args)

		case "done", "exit", "quit", "q":
			fmt.Println("  Exiting editor. Changes are live in memory — use 'save' first if you want them on disk.")
			return

		default:
			fmt.Printf("  Unknown command: %q  (type 'help')\n", cmd)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Commands
// ─────────────────────────────────────────────────────────────────────────────

// cmdList lists all messages with a one-line summary.
func (e *Editor) cmdList() {
	if len(e.Messages) == 0 {
		fmt.Println("  No messages. Use 'new' to create one or 'paste' to paste one.")
		return
	}
	fmt.Println()
	for i, m := range e.Messages {
		p, err := hl7.Parse(m)
		if err != nil {
			fmt.Printf("  [%d] (unparseable: %v)\n", i+1, err)
			continue
		}
		fmt.Printf("  [%d] %s\n", i+1, p.SummaryString())
	}
}

// cmdShow shows the raw segments of a message, numbered for easy reference.
func (e *Editor) cmdShow(args []string) {
	idx, msg, ok := e.resolveMessage(args, 0)
	if !ok {
		return
	}
	p, err := hl7.Parse(msg)
	if err != nil {
		fmt.Printf("  Parse error: %v\n", err)
		fmt.Println("  Raw content:")
		fmt.Println(msg)
		return
	}
	fmt.Printf("\n  Message #%d  (Type=%s  ID=%s)\n", idx+1, p.MessageType, p.MessageID)
	fmt.Println("  " + strings.Repeat("─", 60))
	for i, seg := range p.Segments {
		fmt.Printf("  [seg %2d] %s\n", i+1, strings.Join(seg.Fields, "|"))
	}
	phi := p.ContainsPHI()
	if len(phi) > 0 {
		fmt.Printf("\n  PHI fields detected: %s\n", strings.Join(phi, ", "))
	}
}

// cmdNew creates a blank ADT^A01 message template and adds it to the list.
func (e *Editor) cmdNew() {
	now := time.Now().Format("20060102150405")
	msgID := fmt.Sprintf("MSG%d", time.Now().UnixMilli()%100000)

	template := strings.Join([]string{
		"MSH|^~\\&|SEND_APP|SEND_FAC|RECV_APP|RECV_FAC|" + now + "||ADT^A01|" + msgID + "|P|2.5",
		"EVN|A01|" + now,
		"PID|1||MRN00001^^^HOSP||LASTNAME^FIRSTNAME^M||19700101|M|||123 MAIN ST^^CITY^ST^00000",
		"PV1|1|I|WARD^ROOM^BED|||^PHYSICIAN^FIRST|||MED",
	}, "\r")

	e.Messages = append(e.Messages, template)
	fmt.Printf("\n  Created new ADT^A01 message as #%d\n", len(e.Messages))
	fmt.Println("  Use 'show' to view it, 'edit' to modify fields, 'add-seg' to add segments.")
	e.cmdShow([]string{strconv.Itoa(len(e.Messages))})
}

// cmdPaste reads multi-line HL7 from stdin until the user types END or a blank line after content.
// Supports pasting directly from a live system or a log file.
func (e *Editor) cmdPaste(args []string) {
	// Optional: paste into existing message N, or create new
	replaceIdx := -1
	if len(args) > 0 {
		n, err := strconv.Atoi(args[0])
		if err == nil && n >= 1 && n <= len(e.Messages) {
			replaceIdx = n - 1
			fmt.Printf("\n  Pasting into message #%d (will replace it)\n", n)
		}
	}

	fmt.Println()
	fmt.Println("  Paste your HL7 message below.")
	fmt.Println("  You can paste multiple segments — they will be joined into one message.")
	fmt.Println("  Type END on a new line when done, or leave a blank line after the last segment.")
	fmt.Println()

	var lines []string
	blankCount := 0
	for {
		fmt.Print("  > ")
		line, err := e.reader.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")

		if strings.TrimSpace(line) == "END" {
			break
		}
		if strings.TrimSpace(line) == "" {
			blankCount++
			if blankCount >= 2 || (len(lines) > 0 && blankCount >= 1) {
				break
			}
			continue
		}
		blankCount = 0
		lines = append(lines, strings.TrimSpace(line))
	}

	if len(lines) == 0 {
		fmt.Println("  Nothing pasted.")
		return
	}

	// Join and normalize
	raw := strings.Join(lines, "\r")
	raw = strings.ReplaceAll(raw, "\r\n", "\r")
	raw = strings.ReplaceAll(raw, "\n", "\r")

	// Validate it parses
	p, err := hl7.Parse(raw)
	if err != nil {
		fmt.Printf("\n  Warning: pasted content did not parse cleanly: %v\n", err)
		fmt.Println("  Saving it anyway — use 'show' to inspect.")
	} else {
		fmt.Printf("\n  Parsed OK: %s\n", p.SummaryString())
	}

	if replaceIdx >= 0 {
		e.Messages[replaceIdx] = raw
		fmt.Printf("  Replaced message #%d\n", replaceIdx+1)
	} else {
		e.Messages = append(e.Messages, raw)
		fmt.Printf("  Added as message #%d\n", len(e.Messages))
	}

	e.cmdShow([]string{strconv.Itoa(len(e.Messages))})
}

// cmdAddSegment appends or inserts a segment into a message.
// Usage: add-seg <msg#> [after-seg#] <SEGMENT_TEXT>
// Example: add-seg 1 OBX|1|NM|WBC||7.2|10*3/uL
//          add-seg 1 after 3 OBX|1|NM|WBC||7.2|10*3/uL
func (e *Editor) cmdAddSegment(args []string) {
	if len(args) == 0 {
		fmt.Println("  Usage:")
		fmt.Println("    add-seg <msg#> <SEGMENT>          Append segment to message")
		fmt.Println("    add-seg <msg#> after <seg#> <SEG> Insert after segment number")
		fmt.Println()
		fmt.Println("  Examples:")
		fmt.Println("    add-seg 1 OBX|1|NM|WBC^WHITE BLOOD COUNT||7.2|10*3/uL|4.5-11.0|N|||F")
		fmt.Println("    add-seg 1 after 3 OBX|1|NM|GLUCOSE||95|mg/dL|70-110|N|||F")
		fmt.Println("    add-seg 1 NTE|1|L|Patient reports feeling better")
		return
	}

	msgNum, err := strconv.Atoi(args[0])
	if err != nil || msgNum < 1 || msgNum > len(e.Messages) {
		fmt.Printf("  Invalid message number: %s\n", args[0])
		return
	}
	idx := msgNum - 1
	args = args[1:]

	// Check for "after N" positioning
	insertAfter := -1 // -1 means append
	if len(args) >= 2 && strings.ToLower(args[0]) == "after" {
		n, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Printf("  Invalid segment number after 'after': %s\n", args[1])
			return
		}
		insertAfter = n - 1 // 0-based
		args = args[2:]
	}

	if len(args) == 0 {
		fmt.Println("  No segment text provided.")
		fmt.Println("  Or enter it interactively:")
		fmt.Print("  Segment> ")
		line, _ := e.reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			fmt.Println("  Cancelled.")
			return
		}
		args = []string{line}
	}

	segText := strings.Join(args, " ")
	segText = strings.TrimSpace(segText)

	// Validate segment ID (first 3 chars should be alpha)
	segID := ""
	if len(segText) >= 3 {
		segID = segText[:3]
	}
	if segID == "" || strings.ContainsAny(segID, "0123456789|") {
		fmt.Printf("  Warning: segment text doesn't look like a valid HL7 segment (should start with e.g. OBX, NTE, PID)\n")
		fmt.Print("  Continue anyway? (y/N) ")
		confirm, _ := e.reader.ReadString('\n')
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(confirm)), "y") {
			fmt.Println("  Cancelled.")
			return
		}
	}

	// Parse existing message into segments
	segs := splitSegments(e.Messages[idx])

	if insertAfter < 0 || insertAfter >= len(segs) {
		// Append
		segs = append(segs, segText)
		fmt.Printf("  Appended %s to message #%d\n", segID, msgNum)
	} else {
		// Insert after position
		newSegs := make([]string, 0, len(segs)+1)
		newSegs = append(newSegs, segs[:insertAfter+1]...)
		newSegs = append(newSegs, segText)
		newSegs = append(newSegs, segs[insertAfter+1:]...)
		segs = newSegs
		fmt.Printf("  Inserted %s after segment %d in message #%d\n", segID, insertAfter+1, msgNum)
	}

	e.Messages[idx] = strings.Join(segs, "\r")
	e.cmdShow([]string{strconv.Itoa(msgNum)})
}

// cmdDelSegment removes a segment from a message by segment number.
// Usage: del-seg <msg#> <seg#>
func (e *Editor) cmdDelSegment(args []string) {
	if len(args) < 2 {
		fmt.Println("  Usage: del-seg <msg#> <seg#>")
		fmt.Println("  Example: del-seg 1 4   (removes the 4th segment from message 1)")
		return
	}
	msgNum, err1 := strconv.Atoi(args[0])
	segNum, err2 := strconv.Atoi(args[1])
	if err1 != nil || msgNum < 1 || msgNum > len(e.Messages) {
		fmt.Println("  Invalid message number")
		return
	}
	idx := msgNum - 1
	segs := splitSegments(e.Messages[idx])
	if err2 != nil || segNum < 1 || segNum > len(segs) {
		fmt.Printf("  Invalid segment number (message #%d has %d segments)\n", msgNum, len(segs))
		return
	}
	segID := segs[segNum-1][:3]
	if segID == "MSH" {
		fmt.Println("  Cannot delete the MSH segment — it is required in every HL7 message.")
		return
	}
	segs = append(segs[:segNum-1], segs[segNum:]...)
	e.Messages[idx] = strings.Join(segs, "\r")
	fmt.Printf("  Deleted segment %d (%s) from message #%d\n", segNum, segID, msgNum)
	e.cmdShow([]string{strconv.Itoa(msgNum)})
}

// cmdEditField interactively shows a segment's fields and lets the user pick one to edit.
// Usage: edit <msg#> <seg#>
func (e *Editor) cmdEditField(args []string) {
	if len(args) < 2 {
		fmt.Println("  Usage: edit <msg#> <seg#>")
		fmt.Println("  Example: edit 1 3   (edit fields of segment 3 in message 1)")
		return
	}
	msgNum, err1 := strconv.Atoi(args[0])
	segNum, err2 := strconv.Atoi(args[1])
	if err1 != nil || msgNum < 1 || msgNum > len(e.Messages) {
		fmt.Println("  Invalid message number")
		return
	}
	idx := msgNum - 1
	segs := splitSegments(e.Messages[idx])
	if err2 != nil || segNum < 1 || segNum > len(segs) {
		fmt.Printf("  Invalid segment number (message #%d has %d segments)\n", msgNum, len(segs))
		return
	}

	segIdx := segNum - 1
	fields := strings.Split(segs[segIdx], "|")
	segID := fields[0]

	fmt.Printf("\n  Segment %d — %s\n", segNum, segID)
	fmt.Println("  " + strings.Repeat("─", 50))
	for i, f := range fields {
		if i == 0 {
			continue // segment ID, not editable as a field
		}
		fmt.Printf("  Field %2d: %s\n", i, f)
	}
	fmt.Println()
	fmt.Print("  Enter field number to edit (or 'cancel'): ")
	input, _ := e.reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" || input == "cancel" {
		fmt.Println("  Cancelled.")
		return
	}
	fieldNum, err := strconv.Atoi(input)
	if err != nil || fieldNum < 1 || fieldNum >= len(fields) {
		fmt.Printf("  Invalid field number: %s\n", input)
		return
	}
	fmt.Printf("  Current value: %q\n", fields[fieldNum])
	fmt.Print("  New value: ")
	newVal, _ := e.reader.ReadString('\n')
	newVal = strings.TrimRight(newVal, "\r\n")

	fields[fieldNum] = newVal
	segs[segIdx] = strings.Join(fields, "|")
	e.Messages[idx] = strings.Join(segs, "\r")
	fmt.Printf("  Updated %s field %d → %q\n", segID, fieldNum, newVal)
}

// cmdSetField sets a specific field directly without the interactive prompt.
// Usage: set <msg#> <seg#> <field#> <value>
// Example: set 1 2 5 SMITH^JOHN
func (e *Editor) cmdSetField(args []string) {
	if len(args) < 4 {
		fmt.Println("  Usage: set <msg#> <seg#> <field#> <value>")
		fmt.Println("  Example: set 1 3 5 DOE^JANE^M     (set field 5 of segment 3 in message 1)")
		return
	}
	msgNum, _ := strconv.Atoi(args[0])
	segNum, _ := strconv.Atoi(args[1])
	fieldNum, _ := strconv.Atoi(args[2])
	newVal := strings.Join(args[3:], " ")

	if msgNum < 1 || msgNum > len(e.Messages) {
		fmt.Println("  Invalid message number")
		return
	}
	idx := msgNum - 1
	segs := splitSegments(e.Messages[idx])
	if segNum < 1 || segNum > len(segs) {
		fmt.Printf("  Invalid segment number (message #%d has %d segments)\n", msgNum, len(segs))
		return
	}
	fields := strings.Split(segs[segNum-1], "|")
	// Extend fields slice if needed
	for len(fields) <= fieldNum {
		fields = append(fields, "")
	}
	old := fields[fieldNum]
	fields[fieldNum] = newVal
	segs[segNum-1] = strings.Join(fields, "|")
	e.Messages[idx] = strings.Join(segs, "\r")
	fmt.Printf("  Set message #%d, segment %d (%s), field %d: %q → %q\n",
		msgNum, segNum, fields[0], fieldNum, old, newVal)
}

// cmdDelMessage removes an entire message from the list.
func (e *Editor) cmdDelMessage(args []string) {
	if len(args) == 0 {
		fmt.Println("  Usage: del-msg <msg#>")
		return
	}
	n, err := strconv.Atoi(args[0])
	if err != nil || n < 1 || n > len(e.Messages) {
		fmt.Printf("  Invalid message number: %s\n", args[0])
		return
	}
	fmt.Printf("  Delete message #%d? (y/N) ", n)
	confirm, _ := e.reader.ReadString('\n')
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(confirm)), "y") {
		fmt.Println("  Cancelled.")
		return
	}
	e.Messages = append(e.Messages[:n-1], e.Messages[n:]...)
	fmt.Printf("  Deleted message #%d. %d message(s) remaining.\n", n, len(e.Messages))
}

// cmdDuplicate copies a message and appends it to the list.
func (e *Editor) cmdDuplicate(args []string) {
	idx, msg, ok := e.resolveMessage(args, 0)
	if !ok {
		return
	}
	// Give the copy a new message ID and timestamp
	now := time.Now().Format("20060102150405")
	newID := fmt.Sprintf("MSG%d", time.Now().UnixMilli()%100000)
	copy_ := rewriteMSHFields(msg, now, newID)
	e.Messages = append(e.Messages, copy_)
	fmt.Printf("  Duplicated message #%d as #%d (new ID=%s)\n", idx+1, len(e.Messages), newID)
}

// cmdSave writes all messages to a file.
// Usage: save          (saves to the original file path)
//        save <path>   (saves to a new file)
func (e *Editor) cmdSave(args []string) {
	path := e.FilePath
	if len(args) > 0 {
		path = args[0]
	}
	if path == "" {
		fmt.Print("  Save to file path: ")
		input, _ := e.reader.ReadString('\n')
		path = strings.TrimSpace(input)
		if path == "" {
			fmt.Println("  Cancelled.")
			return
		}
	}

	var sb strings.Builder
	for i, msg := range e.Messages {
		// Normalize to \n for file storage (readable in any editor)
		normalized := strings.ReplaceAll(msg, "\r", "\n")
		sb.WriteString(normalized)
		if i < len(e.Messages)-1 {
			sb.WriteString("\n\n")
		}
	}
	sb.WriteString("\n")

	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		fmt.Printf("  Save error: %v\n", err)
		return
	}
	e.FilePath = path
	fmt.Printf("  Saved %d message(s) to %s\n", len(e.Messages), path)
}

// cmdImport reads an additional file and appends its messages to the current list.
func (e *Editor) cmdImport(args []string) {
	if len(args) == 0 {
		fmt.Println("  Usage: import <filepath>")
		return
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Printf("  Read error: %v\n", err)
		return
	}
	content := string(data)
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	var imported []string
	if strings.Contains(content, "\n\n") {
		for _, block := range strings.Split(content, "\n\n") {
			block = strings.TrimSpace(block)
			if strings.HasPrefix(block, "MSH") {
				imported = append(imported, block)
			}
		}
	}
	if len(imported) == 0 {
		imported = splitByMSH(content)
	}

	before := len(e.Messages)
	e.Messages = append(e.Messages, imported...)
	fmt.Printf("  Imported %d message(s) from %s (total now: %d)\n",
		len(e.Messages)-before, args[0], len(e.Messages))
}

// cmdExport writes a single message to a file.
// Usage: export <msg#> <filepath>
func (e *Editor) cmdExport(args []string) {
	if len(args) < 2 {
		fmt.Println("  Usage: export <msg#> <filepath>")
		return
	}
	n, err := strconv.Atoi(args[0])
	if err != nil || n < 1 || n > len(e.Messages) {
		fmt.Println("  Invalid message number")
		return
	}
	path := args[1]
	normalized := strings.ReplaceAll(e.Messages[n-1], "\r", "\n")
	if err := os.WriteFile(path, []byte(normalized+"\n"), 0644); err != nil {
		fmt.Printf("  Export error: %v\n", err)
		return
	}
	fmt.Printf("  Exported message #%d to %s\n", n, path)
}

// cmdValidate checks all messages for basic HL7 structural validity.
func (e *Editor) cmdValidate(args []string) {
	if len(e.Messages) == 0 {
		fmt.Println("  No messages to validate.")
		return
	}
	targets := e.Messages
	startIdx := 0
	if len(args) > 0 {
		n, err := strconv.Atoi(args[0])
		if err == nil && n >= 1 && n <= len(e.Messages) {
			targets = []string{e.Messages[n-1]}
			startIdx = n - 1
		}
	}

	fmt.Println()
	allOK := true
	for i, msg := range targets {
		n := startIdx + i + 1
		p, err := hl7.Parse(msg)
		if err != nil {
			fmt.Printf("  [%d] ✗ INVALID: %v\n", n, err)
			allOK = false
			continue
		}
		issues := []string{}
		// Check MSH required fields
		msh := p.GetSegment("MSH")
		if msh == nil {
			issues = append(issues, "missing MSH segment")
		} else {
			if msh.Field(9) == "" {
				issues = append(issues, "MSH-9 (message type) is empty")
			}
			if msh.Field(10) == "" {
				issues = append(issues, "MSH-10 (message ID) is empty")
			}
			if msh.Field(12) == "" {
				issues = append(issues, "MSH-12 (version) is empty")
			}
		}
		if len(issues) > 0 {
			fmt.Printf("  [%d] ⚠ WARNINGS: %s\n", n, strings.Join(issues, "; "))
			allOK = false
		} else {
			fmt.Printf("  [%d] ✓ OK — %s\n", n, p.SummaryString())
		}
	}
	if allOK {
		fmt.Println("\n  All messages valid.")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func (e *Editor) resolveMessage(args []string, argIdx int) (int, string, bool) {
	n := 1
	if len(e.Messages) == 0 {
		fmt.Println("  No messages. Use 'new' or 'paste' first.")
		return 0, "", false
	}
	if len(args) > argIdx {
		parsed, err := strconv.Atoi(args[argIdx])
		if err != nil || parsed < 1 || parsed > len(e.Messages) {
			fmt.Printf("  Invalid message number: %s (have %d messages)\n", args[argIdx], len(e.Messages))
			return 0, "", false
		}
		n = parsed
	} else if len(e.Messages) > 1 {
		fmt.Printf("  Tip: specify message number (e.g. 'show 2'). Showing message #1.\n")
	}
	return n - 1, e.Messages[n-1], true
}

func (e *Editor) printHelp() {
	fmt.Println(`
  VIEWING
    list              List all messages with summary
    show [n]          Show segments of message n (default: 1)
    validate [n]      Validate message structure

  CREATING / PASTING
    new               Create a blank ADT^A01 template
    paste [n]         Paste HL7 from your real system (replaces message n if given)
    dup <n>           Duplicate message n (gets a new ID/timestamp)
    import <file>     Append messages from another .hl7 file

  EDITING
    add-seg <n> <SEG>              Append a segment to message n
    add-seg <n> after <s> <SEG>   Insert segment after segment s
    del-seg <n> <s>               Delete segment s from message n
    edit <n> <s>                  Interactively edit fields of segment s
    set <n> <s> <f> <value>       Directly set field f of segment s

  MANAGING
    del-msg <n>       Delete entire message n
    save [path]       Save all messages to file (default: original file)
    export <n> <path> Export single message n to a file

  SEGMENT EXAMPLES
    add-seg 1 OBX|1|NM|WBC^WHITE BLOOD COUNT||7.2|10*3/uL|4.5-11.0|N|||F
    add-seg 1 OBX|2|NM|RBC^RED BLOOD CELLS||4.5|M/uL|4.2-5.4|N|||F
    add-seg 1 NTE|1|L|Patient fasting for 8 hours prior to draw
    add-seg 1 after 3 DG1|1||I10^HYPERTENSION^ICD10

  fuzz <file>       Load captured HL7 from a text file and auto-fuzz fields
                    while sending live to the target. Options:
                      -host <ip>         Target host
                      -port <n>          Target port
                      -tls-auto          Use TLS (no certs needed)
                      -iter <n>          Iterations (default 100)
                      -delay <ms>        Delay between sends (default 100)
                      -seg <SEG>         Only fuzz segment type e.g. PID
                      -field <n>         Only fuzz field number n
                      -strategy <s>      boundary,injection,format,random,
                                         overflow,encoding,all (default all)
                      -stop-on-crash     Stop if server stops responding
                      -out <file.csv>    Save results to CSV
  Examples:
    fuzz captured.hl7 -host 10.0.0.5 -port 2575 -tls-auto -iter 200
    fuzz captured.hl7 -host 10.0.0.5 -port 2575 -seg PID -strategy injection
    fuzz captured.hl7 -host 10.0.0.5 -port 2575 -iter 500 -out results.csv

  done              Return to main shell`)
}

func splitSegments(msg string) []string {
	msg = strings.ReplaceAll(msg, "\r\n", "\r")
	msg = strings.ReplaceAll(msg, "\n", "\r")
	var segs []string
	for _, s := range strings.Split(msg, "\r") {
		s = strings.TrimSpace(s)
		if s != "" {
			segs = append(segs, s)
		}
	}
	return segs
}

func splitByMSH(content string) []string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")
	var msgs []string
	var current strings.Builder
	for _, seg := range strings.Split(content, "\n") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		if strings.HasPrefix(seg, "MSH") && current.Len() > 0 {
			if msg := strings.TrimSpace(current.String()); msg != "" {
				msgs = append(msgs, msg)
			}
			current.Reset()
		}
		current.WriteString(seg + "\r")
	}
	if current.Len() > 0 {
		if msg := strings.TrimSpace(current.String()); msg != "" {
			msgs = append(msgs, msg)
		}
	}
	return msgs
}

func rewriteMSHFields(msg, newTimestamp, newMsgID string) string {
	segs := splitSegments(msg)
	if len(segs) == 0 {
		return msg
	}
	fields := strings.Split(segs[0], "|")
	if len(fields) > 7 {
		fields[7] = newTimestamp
	}
	if len(fields) > 10 {
		fields[10] = newMsgID
	}
	segs[0] = strings.Join(fields, "|")
	return strings.Join(segs, "\r")
}

// cmdFuzz launches a fuzzing session from the editor shell.
// Usage: fuzz <file> [options]
func (e *Editor) cmdFuzz(args []string) {
	if len(args) == 0 {
		fmt.Println("  Usage: fuzz <captured_file.hl7> [options]")
		fmt.Println("  Type 'help' for full option list.")
		return
	}

	cfg := FuzzConfig{
		TargetFile:  args[0],
		Host:        "localhost",
		Port:        2575,
		Iterations:  100,
		DelayMs:     100,
		Strategies:  []string{"all"},
		StopOnCrash: false,
	}

	// Parse remaining flags
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "-host":
			if i+1 < len(rest) {
				cfg.Host = rest[i+1]
				i++
			}
		case "-port":
			if i+1 < len(rest) {
				if n, err := strconv.Atoi(rest[i+1]); err == nil {
					cfg.Port = n
				}
				i++
			}
		case "-tls-auto":
			cfg.TLSAuto = true
			cfg.SkipVerify = true
		case "-iter":
			if i+1 < len(rest) {
				if n, err := strconv.Atoi(rest[i+1]); err == nil {
					cfg.Iterations = n
				}
				i++
			}
		case "-delay":
			if i+1 < len(rest) {
				if n, err := strconv.Atoi(rest[i+1]); err == nil {
					cfg.DelayMs = n
				}
				i++
			}
		case "-seg":
			if i+1 < len(rest) {
				cfg.SegmentFilter = strings.ToUpper(rest[i+1])
				i++
			}
		case "-field":
			if i+1 < len(rest) {
				if n, err := strconv.Atoi(rest[i+1]); err == nil {
					cfg.FieldFilter = n
				}
				i++
			}
		case "-strategy":
			if i+1 < len(rest) {
				cfg.Strategies = strings.Split(rest[i+1], ",")
				i++
			}
		case "-out":
			if i+1 < len(rest) {
				cfg.OutputFile = rest[i+1]
				i++
			}
		case "-stop-on-crash":
			cfg.StopOnCrash = true
		case "-tag":
			if i+1 < len(rest) {
				cfg.Tag = rest[i+1]
				i++
			}
		case "-sending-app":
			if i+1 < len(rest) {
				cfg.SendingApp = rest[i+1]
				i++
			}
		case "-sending-facility":
			if i+1 < len(rest) {
				cfg.SendingFacility = rest[i+1]
				i++
			}
		}
	}

	logFn := func(format string, args ...interface{}) {
		fmt.Printf("  [DBG] "+format+"\n", args...)
	}

	session, err := NewFuzzSession(cfg, logFn)
	if err != nil {
		fmt.Printf("  Fuzz error: %v\n", err)
		return
	}

	fmt.Printf("\n  Loaded %d message(s) from %s\n", session.MessageCount(), cfg.TargetFile)
	fmt.Print("  Start fuzzing? (y/N) ")
	line, _ := e.reader.ReadString('\n')
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "y") {
		fmt.Println("  Cancelled.")
		return
	}

	session.Run()
}

// cmdSanitize fixes common ACK-blocking issues in loaded messages.
// Usage: sanitize [n]   — sanitize message n, or all if n omitted
//        fix [n]        — alias
func (e *Editor) cmdSanitize(args []string) {
	if len(e.Messages) == 0 {
		fmt.Println("  No messages loaded. Use 'import', 'paste', or 'new' first.")
		return
	}

	opts := DefaultSanitizeOptions()

	// Parse optional overrides from args
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-mrn":
			if i+1 < len(args) {
				opts.DefaultMRN = args[i+1]
				i++
			}
		case "-name":
			if i+1 < len(args) {
				opts.DefaultPatientName = args[i+1]
				i++
			}
		case "-version":
			if i+1 < len(args) {
				opts.DefaultVersion = args[i+1]
				i++
			}
		case "-sending-app":
			if i+1 < len(args) {
				opts.SendingApp = args[i+1]
				i++
			}
		case "-receiving-app":
			if i+1 < len(args) {
				opts.ReceivingApp = args[i+1]
				i++
			}
		case "-keep-sft":
			opts.RemoveUnsupported = false
		case "-keep-ft1":
			opts.RemoveEmptyFT1 = false
		}
	}

	// Determine which messages to sanitize
	targetIdx := -1 // -1 = all
	for _, arg := range args {
		if n, err := strconv.Atoi(arg); err == nil && n >= 1 && n <= len(e.Messages) {
			targetIdx = n - 1
			break
		}
	}

	if targetIdx >= 0 {
		// Sanitize single message
		res := Sanitize(e.Messages[targetIdx], opts)
		e.Messages[targetIdx] = res.Sanitized
		PrintSanitizeReport([]SanitizeResult{res})
		fmt.Println()
		e.cmdShow([]string{strconv.Itoa(targetIdx + 1)})
	} else {
		// Sanitize all
		fmt.Printf("  Sanitizing %d message(s)...\n", len(e.Messages))
		sanitized, results := SanitizeAll(e.Messages, opts)
		e.Messages = sanitized
		PrintSanitizeReport(results)
	}
}
