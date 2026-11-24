package ydentifi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/keepalive"
)

// isolateFromEnv clears every variable New reads, so a test sees only the
// configuration it sets.
func isolateFromEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"YDFI_SERVER_ADDR", "YDFI_SERVER_NAME", "YDFI_TLS_CERT_PATH", "YDFI_TLS_KEY_PATH", "YDFI_TLS_CA_PATH"} {
		t.Setenv(name, "")
	}
}

// selfSigned returns a certificate valid from notBefore to notAfter, named
// cn, and its key, as PEM.
func selfSigned(t *testing.T, cn string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
}

// writePair writes a certificate and key into dir, readable by the owner
// only, and returns their paths.
func writePair(t *testing.T, dir string, certPEM, keyPEM []byte) (certFile, keyFile string) {
	t.Helper()
	certFile, keyFile = filepath.Join(dir, "rp.crt"), filepath.Join(dir, "rp.key")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func validPair(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	return selfSigned(t, cn, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
}

// newTestClient builds a client for an address nothing listens on; New does
// not connect.
func newTestClient(t *testing.T, opts ...Option) *Client {
	t.Helper()
	isolateFromEnv(t)
	certPEM, keyPEM := validPair(t, "rp")
	c, err := New(append([]Option{WithServerAddr(closedAddr), WithCert(certPEM, keyPEM), WithCA(certPEM)}, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	return c
}

// Options apply in order, and a later one replaces what an earlier one set.
func TestOptionsApplyInOrderAndTheLastWins(t *testing.T) {
	var cfg config
	logger := slog.New(slog.DiscardHandler)
	params := keepalive.ClientParameters{Time: time.Minute}
	dial := grpc.WithUserAgent("x")
	for _, opt := range []Option{
		WithServerAddr("a.example:1"), WithServerAddr("b.example:2"),
		WithServerName("a"), WithServerName("b"),
		WithCert([]byte("c1"), []byte("k1")), WithCert([]byte("c2"), []byte("k2")),
		WithCertFiles("c1.pem", "k1.pem"), WithCertFiles("c2.pem", "k2.pem"),
		WithUserAgent("ua1"), WithUserAgent("ua2"),
		WithKeepalive(keepalive.ClientParameters{}), WithKeepalive(params),
		WithDialOptions(grpc.WithUserAgent("y"), grpc.WithUserAgent("z")), WithDialOptions(dial),
		WithLogger(slog.Default()), WithLogger(logger),
	} {
		opt(&cfg)
	}
	if cfg.addr != "b.example:2" || cfg.serverName != "b" || string(cfg.certPEM) != "c2" || string(cfg.keyPEM) != "k2" ||
		cfg.certFile != "c2.pem" || cfg.keyFile != "k2.pem" || cfg.userAgent != "ua2" || *cfg.keepalive != params ||
		len(cfg.dialOptions) != 1 || cfg.logger != logger {
		t.Fatalf("config %+v", cfg)
	}

	WithCAFile("ca1.pem")(&cfg)
	WithCAFile("ca2.pem")(&cfg)
	WithCA([]byte("ca1"))(&cfg)
	WithCA([]byte("ca2"))(&cfg)
	if cfg.caFile != "ca2.pem" || string(cfg.caPEM) != "ca2" {
		t.Fatalf("CA options: file %q, PEM %q", cfg.caFile, cfg.caPEM)
	}
}

// The environment supplies what the options leave unset, and an option
// takes precedence over its variable.
func TestNewReadsTheEnvironmentForWhatTheOptionsLeaveUnset(t *testing.T) {
	isolateFromEnv(t)
	certPEM, keyPEM := validPair(t, "rp")
	certFile, keyFile := writePair(t, t.TempDir(), certPEM, keyPEM)
	t.Setenv("YDFI_SERVER_ADDR", "127.0.0.1:1")
	t.Setenv("YDFI_SERVER_NAME", "rp.example")
	t.Setenv("YDFI_TLS_CERT_PATH", certFile)
	t.Setenv("YDFI_TLS_KEY_PATH", keyFile)
	t.Setenv("YDFI_TLS_CA_PATH", filepath.Join(t.TempDir(), "absent-ca.pem"))
	if _, err := New(); !errors.Is(err, ErrConfiguration) || !strings.Contains(err.Error(), "absent-ca.pem") {
		t.Fatalf("New with an absent CA file in the environment: %v", err)
	}
	if _, err := New(WithCA(nil)); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("WithCA(nil) is no CA bundle, so the environment's file is read and refused: %v", err)
	}
	if _, err := New(WithCAFile(""), WithCertFiles(certFile, keyFile)); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("WithCAFile(\"\") is no CA bundle, so the environment's file is read and refused: %v", err)
	}

	// Options take precedence over every variable, even one naming a file
	// that does not exist.
	missing := filepath.Join(t.TempDir(), "missing.pem")
	t.Setenv("YDFI_SERVER_ADDR", "")
	t.Setenv("YDFI_TLS_CERT_PATH", missing)
	t.Setenv("YDFI_TLS_KEY_PATH", missing)
	t.Setenv("YDFI_TLS_CA_PATH", missing)
	ca, _ := validPair(t, "ca")
	c, err := New(WithServerAddr("auth.example.com:443"), WithCert(certPEM, keyPEM), WithCA(ca))
	if err != nil {
		t.Fatalf("New with options over a broken environment: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	// The environment's certificate files are used only as a pair.
	t.Setenv("YDFI_TLS_CERT_PATH", certFile)
	t.Setenv("YDFI_TLS_KEY_PATH", "")
	t.Setenv("YDFI_TLS_CA_PATH", "")
	if _, err := New(WithServerAddr("auth.example.com:443")); !errors.Is(err, ErrConfiguration) || !strings.Contains(err.Error(), "certificate and key are required") {
		t.Fatalf("New with a certificate path and no key path: %v", err)
	}
}

// SDK-007: the same material given twice is refused. A certificate or a CA
// bundle given both as files and as PEM is refused before any file is read,
// whatever the order of the options. One option given twice is not an
// error: the last value given is used.
func TestSDK007_SameMaterialTwice(t *testing.T) {
	isolateFromEnv(t)
	certPEM, keyPEM := validPair(t, "rp")
	for name, opts := range map[string][]Option{
		"the certificate as bytes, then by file": {WithCert([]byte("c"), []byte("k")), WithCertFiles("/nonexistent/c.pem", "/nonexistent/k.pem")},
		"the certificate by file, then as bytes": {WithCertFiles("/nonexistent/c.pem", "/nonexistent/k.pem"), WithCert([]byte("c"), []byte("k"))},
		"the CA as bytes, then by file":          {WithCert(certPEM, keyPEM), WithCA([]byte("ca")), WithCAFile("/nonexistent/ca.pem")},
		"the CA by file, then as bytes":          {WithCert(certPEM, keyPEM), WithCAFile("/nonexistent/ca.pem"), WithCA([]byte("ca"))},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := New(append(opts, WithServerAddr(closedAddr))...)
			if c != nil || !errors.Is(err, ErrConfiguration) || !strings.Contains(err.Error(), "both as") || strings.Contains(err.Error(), "nonexistent") {
				t.Fatalf("New: %v; want the conflict refused", err)
			}
		})
	}
	t.Run("an option given twice", func(t *testing.T) {
		// Port 0 is refused, so each pair of values builds a client only
		// when the last one is used.
		for name, opts := range map[string][]Option{
			"WithServerAddr, a refused address and then a valid one": {WithServerAddr("localhost:0"), WithServerAddr(closedAddr), WithCert(certPEM, keyPEM), WithCA(certPEM)},
			"WithCert, a refused pair and then a valid one":          {WithServerAddr(closedAddr), WithCert([]byte("c"), []byte("k")), WithCert(certPEM, keyPEM), WithCA(certPEM)},
			"WithCert, the same pair twice":                          {WithServerAddr(closedAddr), WithCert(certPEM, keyPEM), WithCert(certPEM, keyPEM), WithCA(certPEM)},
		} {
			c, err := New(opts...)
			if err != nil {
				t.Fatalf("%s: %v; want a client built from the last value", name, err)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
		}
		for name, opts := range map[string][]Option{
			"WithServerAddr, a valid address and then a refused one": {WithServerAddr(closedAddr), WithServerAddr("localhost:0"), WithCert(certPEM, keyPEM), WithCA(certPEM)},
			"WithCert, a valid pair and then a refused one":          {WithServerAddr(closedAddr), WithCert(certPEM, keyPEM), WithCert([]byte("c"), []byte("k")), WithCA(certPEM)},
		} {
			c, err := New(opts...)
			wantConfigErr(t, name, c, err)
		}
	})
}

// New refuses dial options gRPC cannot build a connection with.
func TestNewRefusesUnusableDialOptions(t *testing.T) {
	isolateFromEnv(t)
	certPEM, keyPEM := validPair(t, "rp")
	_, err := New(WithServerAddr("auth.example.com:443"), WithCert(certPEM, keyPEM), WithCA(certPEM),
		WithDialOptions(grpc.WithDefaultServiceConfig("not a service config")))
	if !errors.Is(err, ErrConfiguration) {
		t.Fatalf("New: %v; want ErrConfiguration", err)
	}
}

// Every optional setting builds a client.
func TestNewWithEveryOption(t *testing.T) {
	isolateFromEnv(t)
	certPEM, keyPEM := validPair(t, "rp")
	ca, _ := validPair(t, "ca")
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(WithServerAddr("[::1]:443"), WithServerName("auth.example.com"), WithCert(certPEM, keyPEM),
		WithCAFile(caFile), WithUserAgent("test/1"), WithKeepalive(keepalive.ClientParameters{Time: time.Minute}),
		WithDialOptions(grpc.WithIdleTimeout(time.Minute)), WithLogger(nil))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.logger != slog.Default() {
		t.Error("a nil logger did not select slog.Default()")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("a second Close: %v; want the first Close's result", err)
	}
}

// SDK-060: a string argument that is not valid UTF-8 is refused at once,
// before any request is sent, by every method that takes one. The client's
// address names a closed port, so an attempt to send would end with
// ErrUnavailable; the connection stays idle throughout.
func TestSDK060_TextThatCannotBeEncoded(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	const bad = "\xff"
	const user = "00000000000000000000000000000000000000000000000000000000000000ff"
	const device = "00000000-0000-0000-0000-000000000000"
	first := func(seq func(func(string, error) bool)) error {
		var got error
		seq(func(_ string, err error) bool { got = err; return false })
		return got
	}
	calls := map[string]func() error{
		"BulkCreateUsers": func() error { return first(c.BulkCreateUsers(ctx, 1, bad)) },
		"GetUser":         func() error { _, err := c.GetUser(ctx, bad); return err },
		"ExportUsers": func() error {
			for _, err := range c.ExportUsers(ctx, bad) {
				return err
			}
			return nil
		},
		"UpdateUserStatus":        func() error { return c.UpdateUserStatus(ctx, bad, UserStatusLocked) },
		"DeleteUser":              func() error { return c.DeleteUser(ctx, bad) },
		"UnlockUserRequestLimits": func() error { return c.UnlockUserRequestLimits(ctx, bad) },
		"ListDevicesForUser":      func() error { _, err := c.ListDevicesForUser(ctx, bad); return err },
		"RevokeDevice opaqueID":   func() error { return c.RevokeDevice(ctx, bad, device) },
		"RevokeDevice deviceID":   func() error { return c.RevokeDevice(ctx, user, bad) },
		"BanDevice opaqueID":      func() error { _, err := c.BanDevice(ctx, bad, device, "r"); return err },
		"BanDevice deviceID":      func() error { _, err := c.BanDevice(ctx, user, bad, "r"); return err },
		"BanDevice reason":        func() error { _, err := c.BanDevice(ctx, user, device, bad); return err },
		"UnbanDevice OpaqueID":    func() error { return c.UnbanDevice(ctx, UnbanDeviceRequest{OpaqueID: bad, DeviceID: device}) },
		"UnbanDevice DeviceID":    func() error { return c.UnbanDevice(ctx, UnbanDeviceRequest{OpaqueID: user, DeviceID: bad}) },
		"UnbanDevice PermanentID": func() error { return c.UnbanDevice(ctx, UnbanDeviceRequest{OpaqueID: user, PermanentID: bad}) },
		"IssueAuthChallenge OpaqueID": func() error {
			_, err := c.IssueAuthChallenge(ctx, IssueAuthChallengeRequest{OpaqueID: bad})
			return err
		},
		"IssueAuthChallenge ChallengeID": func() error {
			_, err := c.IssueAuthChallenge(ctx, IssueAuthChallengeRequest{OpaqueID: user, ChallengeID: bad})
			return err
		},
		"AwaitChallenge": func() error {
			for _, err := range c.AwaitChallenge(ctx, bad) {
				return err
			}
			return nil
		},
		"ListActiveChallenges":    func() error { _, err := c.ListActiveChallenges(ctx, bad); return err },
		"IssueUserTOTPEnrollment": func() error { _, err := c.IssueUserTOTPEnrollment(ctx, bad, true); return err },
		"VerifyUserTOTP opaqueID": func() error { _, err := c.VerifyUserTOTP(ctx, bad, "000000"); return err },
		"VerifyUserTOTP code":     func() error { _, err := c.VerifyUserTOTP(ctx, user, bad); return err },
		"IssueEnrollmentInvite": func() error {
			_, err := c.IssueEnrollmentInvite(ctx, IssueEnrollmentInviteRequest{OpaqueID: bad})
			return err
		},
		"IssueRecoveryInvite": func() error {
			_, err := c.IssueRecoveryInvite(ctx, IssueRecoveryInviteRequest{OpaqueID: bad})
			return err
		},
	}
	for name, call := range calls {
		start := time.Now()
		err := call()
		took := time.Since(start)
		var se *StatusError
		if !errors.Is(err, ErrInvalidArgument) || errors.As(err, &se) || !strings.Contains(err.Error(), "not valid UTF-8") {
			t.Errorf("%s: %v; want the local UTF-8 refusal, which carries no reason and no field", name, err)
		}
		if took > localSlack {
			t.Errorf("%s: refused after %v; want at once, within %v", name, took, localSlack)
		}
	}
	if state := c.conn.GetState(); state != connectivity.Idle {
		t.Fatalf("the connection is %v after the refusals; want Idle: no connection attempted", state)
	}
}

// warnings records the messages and errors logged at Warn.
type warnings struct{ lines []string }

func (w *warnings) Enabled(context.Context, slog.Level) bool { return true }
func (w *warnings) WithAttrs([]slog.Attr) slog.Handler       { return w }
func (w *warnings) WithGroup(string) slog.Handler            { return w }
func (w *warnings) Handle(_ context.Context, r slog.Record) error {
	line := r.Level.String() + " " + r.Message
	r.Attrs(func(a slog.Attr) bool { line += " " + a.Key + "=" + a.Value.String(); return true })
	w.lines = append(w.lines, line)
	return nil
}

// The TLS hook presents each valid pair the files hold, and keeps the
// certificate in use, with a warning, for a pair it cannot use.
func TestClientCertificateReadsTheFilesAtEachHandshake(t *testing.T) {
	isolateFromEnv(t)
	dir := t.TempDir()
	certA, keyA := validPair(t, "rp-a")
	certFile, keyFile := writePair(t, dir, certA, keyA)
	log := &warnings{}
	c, err := New(WithServerAddr("auth.example.com:443"), WithCertFiles(certFile, keyFile), WithCAFile(certFile), WithLogger(slog.New(log)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	presented := func() string {
		t.Helper()
		cert, err := c.clientCertificate(nil)
		if err != nil {
			t.Fatal(err)
		}
		return cert.Leaf.Subject.CommonName
	}
	if got := presented(); got != "rp-a" {
		t.Fatalf("presented %q, want rp-a", got)
	}

	certB, keyB := validPair(t, "rp-b")
	writePair(t, dir, certB, keyB)
	if got := presented(); got != "rp-b" || len(log.lines) != 0 {
		t.Fatalf("after renewal: presented %q, logged %q", got, log.lines)
	}

	now := time.Now()
	future, futureKey := selfSigned(t, "rp-future", now.Add(time.Hour), now.Add(2*time.Hour))
	expired, expiredKey := selfSigned(t, "rp-expired", now.Add(-2*time.Hour), now.Add(-time.Hour))
	certC, _ := validPair(t, "rp-c")
	for _, tc := range []struct {
		name      string
		cert, key []byte
		logged    string
	}{
		{"not yet valid", future, futureKey, "rp.crt is not valid until"},
		{"expired", expired, expiredKey, "rp.crt expired at"},
		{"the key of another certificate", certC, keyB, "parse the certificate and key"},
		{"a corrupt chain", append(append([]byte{}, certB...), corruptCertBlock...), keyB, "parse certificate 2 of the chain"},
	} {
		log.lines = nil
		writePair(t, dir, tc.cert, tc.key)
		if got := presented(); got != "rp-b" {
			t.Errorf("%s: presented %q, want rp-b", tc.name, got)
		}
		if len(log.lines) != 1 || !strings.HasPrefix(log.lines[0], "WARN certificate files not used") || !strings.Contains(log.lines[0], tc.logged) {
			t.Errorf("%s: logged %q", tc.name, log.lines)
		}
	}

	log.lines = nil
	if err := os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	if got := presented(); got != "rp-b" {
		t.Errorf("without a key file: presented %q, want rp-b", got)
	}
	if len(log.lines) != 1 || !strings.Contains(log.lines[0], "read rp.key") || strings.Contains(log.lines[0], dir) {
		t.Errorf("without a key file: logged %q", log.lines)
	}
}

// Under GODEBUG=x509keypairleaf=0, tls.X509KeyPair leaves the leaf unset;
// the dates of a renewed pair are read from a leaf parsed by the client.
func TestClientCertificateReadsARenewedPairWithItsLeafUnparsed(t *testing.T) {
	isolateFromEnv(t)
	t.Setenv("GODEBUG", "x509keypairleaf=0")
	dir := t.TempDir()
	certA, keyA := validPair(t, "rp-a")
	certFile, keyFile := writePair(t, dir, certA, keyA)
	c, err := New(WithServerAddr("auth.example.com:443"), WithCertFiles(certFile, keyFile), WithCAFile(certFile))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	certB, keyB := validPair(t, "rp-b")
	writePair(t, dir, certB, keyB)
	cert, err := c.clientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := cert.Leaf.Subject.CommonName; got != "rp-b" {
		t.Fatalf("after renewal: presented %q, want rp-b", got)
	}
}

// SDK-009: the certificate files are parsed at construction, and a key
// that is not the certificate's is refused there.
func TestSDK009_CertificateFilesThatDoNotParse(t *testing.T) {
	isolateFromEnv(t)
	certA, _ := validPair(t, "rp-a")
	_, keyB := validPair(t, "rp-b")
	certFile, keyFile := writePair(t, t.TempDir(), certA, keyB)
	if _, err := New(WithServerAddr("auth.example.com:443"), WithCertFiles(certFile, keyFile), WithCAFile(certFile)); !errors.Is(err, ErrConfiguration) {
		t.Fatalf("New: %v; want ErrConfiguration", err)
	}
}
