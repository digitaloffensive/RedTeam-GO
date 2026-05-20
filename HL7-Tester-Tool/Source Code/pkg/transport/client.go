// Package transport handles TCP and TLS connections for HL7 MLLP communication.
package transport

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hl7-security-tester/pkg/hl7"
)

// Config holds connection configuration.
type Config struct {
	Host        string
	Port        int
	UseTLS      bool          // Use TLS with certificate verification (requires -ca or system roots)
	TLSAuto     bool          // Use TLS without providing any certs — accepts any server cert.
	                          // Useful for testing TLS handshake when you don't have the CA file.
	                          // Combines with -cert/-key if you still want a client certificate.
	CertFile    string        // Client cert for mutual TLS
	KeyFile     string        // Client key for mutual TLS
	CAFile      string        // CA cert to verify server
	SkipVerify  bool          // INSECURE: skip TLS verification (used to test if server allows it)
	Timeout     time.Duration
	ReadTimeout time.Duration
	NoResponse  bool   // Do not wait for an ACK — fire and forget.

	// MSH application identity — overrides values in the message file.
	// The receiver uses these to decide whether to accept the connection.
	// Ask the receiving system admin for the exact strings they expect.
	SendingApp      string // MSH-3: your application name  (e.g. "MYSYSTEM")
	SendingFacility string // MSH-4: your facility name     (e.g. "MYHOSP")
	ReceivingApp    string // MSH-5: target application     (e.g. "RHAPSODY")
	ReceivingFacility string // MSH-6: target facility      (e.g. "DESTHOSP")

	// Pre-auth: some servers send a challenge string immediately on connect
	// before accepting MLLP frames (e.g. a username:password prompt or token).
	// Set PreAuthString to the exact response the server expects.
	PreAuthString string // Raw string to send immediately after TCP/TLS connect
}

// ConnectionInfo contains details about the established connection.
type ConnectionInfo struct {
	LocalAddr   string
	RemoteAddr  string
	TLSVersion  string
	CipherSuite string
	PeerCerts   []*x509.Certificate
	UsedTLS     bool
}

// Client is a bidirectional HL7 MLLP client.
type Client struct {
	cfg    Config
	conn   net.Conn
	reader *bufio.Reader
	Info   ConnectionInfo
}

// Dial establishes a connection to the HL7 receiver.
func Dial(cfg Config) (*Client, error) {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	c := &Client{cfg: cfg}

	if cfg.UseTLS || cfg.TLSAuto {
		tlsCfg, err := buildTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("TLS config error: %w", err)
		}
		dialer := &net.Dialer{Timeout: timeout}
		tlsConn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("TLS dial failed: %w", err)
		}

		// Complete the handshake explicitly so we can inspect the negotiated state
		if err := tlsConn.Handshake(); err != nil {
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}

		c.conn = tlsConn

		// Capture TLS details
		state := tlsConn.ConnectionState()
		c.Info = ConnectionInfo{
			LocalAddr:   tlsConn.LocalAddr().String(),
			RemoteAddr:  tlsConn.RemoteAddr().String(),
			TLSVersion:  tlsVersionName(state.Version),
			CipherSuite: tls.CipherSuiteName(state.CipherSuite),
			PeerCerts:   state.PeerCertificates,
			UsedTLS:     true,
		}
	} else {
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			return nil, fmt.Errorf("TCP dial failed: %w", err)
		}
		c.conn = conn
		c.Info = ConnectionInfo{
			LocalAddr:  conn.LocalAddr().String(),
			RemoteAddr: conn.RemoteAddr().String(),
			UsedTLS:    false,
		}
	}

	c.reader = bufio.NewReaderSize(c.conn, 65536)

	// Pre-auth: send challenge response immediately after connect if configured.
	// The server reads this before it will accept any MLLP frames.
	if cfg.PreAuthString != "" {
		_ = c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := fmt.Fprint(c.conn, cfg.PreAuthString); err != nil {
			c.conn.Close()
			return nil, fmt.Errorf("pre-auth send failed: %w", err)
		}
		_ = c.conn.SetWriteDeadline(time.Time{})

		// Read the server's response to the pre-auth (up to 1s)
		_ = c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		preResp := make([]byte, 512)
		n, _ := c.conn.Read(preResp)
		_ = c.conn.SetReadDeadline(time.Time{})
		if n > 0 {
			resp := strings.TrimSpace(string(preResp[:n]))
			if strings.Contains(strings.ToLower(resp), "fail") ||
				strings.Contains(strings.ToLower(resp), "denied") ||
				strings.Contains(strings.ToLower(resp), "invalid") ||
				strings.Contains(strings.ToLower(resp), "error") {
				c.conn.Close()
				return nil, fmt.Errorf("pre-auth rejected by server: %q", resp)
			}
		}
	}

	return c, nil
}

// Send sends an HL7 message over MLLP and returns the raw response bytes.
// Uses a bufio.Writer to ensure the entire MLLP frame is flushed to the TCP
// stack in one shot — prevents the receiver seeing 0-byte / premature EOF.
func (c *Client) Send(msg string) ([]byte, time.Duration, error) {
	// Rewrite MSH identity fields if configured — server uses these to authenticate
	if c.cfg.SendingApp != "" || c.cfg.SendingFacility != "" ||
		c.cfg.ReceivingApp != "" || c.cfg.ReceivingFacility != "" {
		msg = rewriteMSHIdentity(msg, c.cfg.SendingApp, c.cfg.SendingFacility,
			c.cfg.ReceivingApp, c.cfg.ReceivingFacility)
	}
	frame := hl7.WrapMLLP(msg) // WrapMLLP handles all normalization internally

	readTimeout := c.cfg.ReadTimeout
	if readTimeout == 0 {
		readTimeout = 60 * time.Second // generous default — many HL7 receivers are slow to ACK
	}

	start := time.Now()

	// Write through a bufio.Writer so the entire MLLP frame goes out as one
	// TCP segment. Without this some stacks split the write, and .NET / Java
	// HL7 listeners that call Read() once see an empty first chunk and bail
	// with "unexpected EOF or 0 bytes from the transport stream".
	w := bufio.NewWriterSize(c.conn, len(frame)+8)
	if _, err := w.Write(frame); err != nil {
		return nil, 0, fmt.Errorf("write error: %w", err)
	}
	if err := w.Flush(); err != nil {
		return nil, 0, fmt.Errorf("flush error: %w", err)
	}
	elapsed := time.Since(start)

	// -no-response mode: message sent, do not wait for ACK.
	// Use when the receiver processes messages but never sends an ACK back.
	if c.cfg.NoResponse {
		return []byte("[no-response mode: message sent, ACK not expected]"), elapsed, nil
	}

	_ = c.conn.SetReadDeadline(time.Now().Add(readTimeout))
	resp, err := readMLLP(c.reader)
	elapsed = time.Since(start)
	_ = c.conn.SetReadDeadline(time.Time{})

	// EOF with data means server closed connection after responding — valid.
	if err != nil && len(resp) > 0 {
		return resp, elapsed, nil
	}
	if err != nil {
		// Give a clear, actionable error instead of a raw i/o timeout
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, elapsed, fmt.Errorf(
				"timed out waiting for ACK after %s\n"+
				"  The message was sent successfully but the receiver did not respond in time.\n"+
				"  Options:\n"+
				"    • Increase timeout:   -read-timeout 120s\n"+
				"    • Skip waiting:       -no-response\n"+
				"    • Check receiver logs to confirm it received the message",
				elapsed.Round(time.Millisecond))
		}
		return nil, elapsed, fmt.Errorf("read error: %w", err)
	}
	return resp, elapsed, nil
}

// SendRaw sends arbitrary bytes without MLLP framing (used for fuzzing/DoS tests).
func (c *Client) SendRaw(data []byte) ([]byte, error) {
	if _, err := c.conn.Write(data); err != nil {
		return nil, fmt.Errorf("write error: %w", err)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := readMLLP(c.reader)
	_ = c.conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// IsConnected checks if the connection appears alive.
func (c *Client) IsConnected() bool {
	return c.conn != nil
}

// readMLLP reads an MLLP-framed response, with multiple fallback strategies:
//   - Standard MLLP: 0x0B ... 0x1C 0x0D
//   - Unframed HL7:  raw MSH... response (some servers skip MLLP on ACKs)
//   - EOF after data: server closed connection after writing response
//   - Deadline exceeded with data buffered: return what we have
func readMLLP(r *bufio.Reader) ([]byte, error) {
	// Peek at the first byte to decide framing strategy
	first, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

	// Standard MLLP framed response
	if first == hl7.MLLPStartBlock {
		var buf []byte
		buf = append(buf, first)
		for {
			b, err := r.ReadByte()
			if err != nil {
				// EOF or deadline with data — return what we have
				if len(buf) > 1 {
					return buf, nil
				}
				return nil, err
			}
			buf = append(buf, b)
			if b == hl7.MLLPEndBlock {
				// Consume optional trailing CR
				if next, err := r.ReadByte(); err == nil {
					if next == hl7.MLLPCarriageRet {
						buf = append(buf, next)
					} else {
						_ = r.UnreadByte()
					}
				}
				return buf, nil
			}
		}
	}

	// Unframed response — server sent raw HL7 without MLLP wrapping.
	// Read until we get a complete MSA segment or connection closes.
	var buf []byte
	buf = append(buf, first)
	for {
		b, err := r.ReadByte()
		if err != nil {
			// EOF or deadline — return whatever we accumulated
			if len(buf) > 0 {
				return buf, nil
			}
			return nil, err
		}
		buf = append(buf, b)

		// Check if we have a complete ACK (ends with MSA segment + \r)
		content := string(buf)
		if strings.Contains(content, "MSA|") &&
			(strings.HasSuffix(strings.TrimRight(content, "\r\n"), "\r") ||
				b == '\r' || b == '\n') {
			// Give a brief moment for any trailing segments
			r.ReadByte() //nolint:errcheck
			return buf, nil
		}
	}
}

// rewriteMSHIdentity replaces MSH-3/4/5/6 in a raw HL7 message.
// Only replaces fields where the override is non-empty, leaving others untouched.
// Skips MSH segments that are structurally invalid (no field separators,
// wrong encoding characters) so deliberately malformed test payloads are preserved.
func rewriteMSHIdentity(msg, sendApp, sendFac, recvApp, recvFac string) string {
	lines := strings.Split(msg, "\r")
	if len(lines) == 0 {
		return msg
	}
	// Find MSH line (should be first, but search to be safe)
	for i, line := range lines {
		if !strings.HasPrefix(line, "MSH") {
			continue
		}
		// Guard: must have field separators and valid encoding chars
		if !strings.Contains(line, "|") {
			break
		}
		fields := strings.Split(line, "|")
		if len(fields) < 5 || len(fields[1]) != 1 || len(fields[2]) != 4 {
			break // malformed MSH — leave it exactly as-is
		}
		// MSH field indices (0=MSH, 1=field-sep, 2=encoding, 3=SendApp, 4=SendFac, 5=RecvApp, 6=RecvFac)
		for len(fields) < 10 {
			fields = append(fields, "")
		}
		if sendApp != "" {
			fields[3] = sendApp
		}
		if sendFac != "" {
			fields[4] = sendFac
		}
		if recvApp != "" {
			fields[5] = recvApp
		}
		if recvFac != "" {
			fields[6] = recvFac
		}
		lines[i] = strings.Join(fields, "|")
		break
	}
	return strings.Join(lines, "\r")
}

func buildTLSConfig(cfg Config) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		ServerName: cfg.Host,
		MinVersion: tls.VersionTLS12,
	}

	// TLSAuto mode: accept any server certificate without verification.
	// This lets you observe the TLS handshake, cipher suite, and certificate
	// details without needing the CA file. Still fully encrypts the channel.
	// -skip-verify does the same but is an explicit INSECURE flag; -tls-auto
	// is the "just make it work" flag for assessment scenarios.
	if cfg.TLSAuto {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // intentional: auto-mode accepts any cert
	} else {
		tlsCfg.InsecureSkipVerify = cfg.SkipVerify //nolint:gosec // intentional for security testing
	}

	// Load CA cert if provided — overrides InsecureSkipVerify for proper chain validation
	if cfg.CAFile != "" {
		tlsCfg.InsecureSkipVerify = false
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert")
		}
		tlsCfg.RootCAs = pool
	}

	// Load client cert if provided — works in both -tls and -tls-auto modes
	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading client cert/key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", v)
	}
}
