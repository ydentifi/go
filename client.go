// Package ydentifi is a Go client for the Ydentifi relying-party API.
//
// # Configuration
//
// New builds a Client from options and environment variables. A server
// address, the relying party's mTLS certificate and key, and the deployment's
// CA bundle are required. A TLS verification name, keepalive parameters, a
// user agent and gRPC dial options may also be given. A certificate given as files is read
// again at each new connection, so a renewed certificate written to the same
// files is used from the next connection onwards.
//
// # Errors
//
// An error that the server returns is a *StatusError, which carries the gRPC
// code, the server's reason and the other details of the status. Each code
// that the server sends matches a sentinel error through errors.Is, and some
// reasons match a sentinel of their own. An invalid configuration matches
// ErrConfiguration, and a string argument that is not valid UTF-8, or a TTL
// below zero or of 2^32 seconds or more, matches ErrInvalidArgument; none
// of these is a *StatusError.
//
// # Concurrency
//
// A Client is safe for concurrent use by multiple goroutines. All calls of
// one Client share one gRPC connection. The iterators that the streaming
// methods return are used by one goroutine at a time.
package ydentifi

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	identitypb "github.com/ydentifi/go/internal/ydfi-proto-go/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Version is the semantic version of this SDK release. The client sends it
// in its default User-Agent.
const Version = "0.1.4"

// Client is a client of the Ydentifi relying-party API. It is safe for
// concurrent use by multiple goroutines and is closed with Close.
type Client struct {
	conn *grpc.ClientConn
	svc  identitypb.IdentityServiceClient

	// certFile and keyFile are the files the certificate is read from at
	// each TLS handshake; both are empty when the certificate was given as
	// PEM. cert is the certificate presented, replaced by each valid pair
	// read from the files. refused is the reason the files were last
	// refused for, or nil after a pair from them is presented; a refusal
	// is logged only when its reason differs from refused, so that each
	// problem is logged once while it lasts.
	certFile, keyFile string
	cert              atomic.Pointer[tls.Certificate]
	refused           atomic.Pointer[string]
	logger            *slog.Logger

	// closeOnce closes the connection once; closeErr is the result that
	// every Close returns.
	closeOnce sync.Once
	closeErr  error
}

// New returns a Client configured by options and environment variables. An
// option takes precedence over the corresponding variable. The variables
// are:
//
//	YDFI_SERVER_ADDR     the server's host, with an optional port (required)
//	YDFI_SERVER_NAME     the TLS verification name, required for an IP address
//	YDFI_TLS_CERT_PATH   the relying party's certificate file (PEM)
//	YDFI_TLS_KEY_PATH    the relying party's private key file (PEM)
//	YDFI_TLS_CA_PATH     the deployment's CA bundle that verifies the server (PEM)
//
// The certificate files are required unless WithCert or WithCertFiles gives
// the certificate, and the CA bundle unless WithCAFile or WithCA gives it.
// The server is trusted only through the deployment's own CA, never through
// the system trust store, and only when its certificate names it a Ydentifi
// server. New does not connect: the connection is made by the first call. An
// invalid or incomplete configuration returns an error that matches
// ErrConfiguration.
func New(opts ...Option) (*Client, error) {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.certPEM != nil && cfg.certFile != "" {
		return nil, configErr("the certificate is given both as files and as PEM")
	}
	if cfg.caPEM != nil && cfg.caFile != "" {
		return nil, configErr("the CA bundle is given both as a file and as PEM")
	}
	if cfg.addr == "" {
		cfg.addr = os.Getenv("YDFI_SERVER_ADDR")
	}
	if cfg.serverName == "" {
		cfg.serverName = os.Getenv("YDFI_SERVER_NAME")
	}
	if cfg.certPEM == nil && cfg.certFile == "" {
		cfg.certFile, cfg.keyFile = os.Getenv("YDFI_TLS_CERT_PATH"), os.Getenv("YDFI_TLS_KEY_PATH")
		if cfg.certFile == "" || cfg.keyFile == "" {
			cfg.certFile, cfg.keyFile = "", ""
		}
	}
	if cfg.caPEM == nil && cfg.caFile == "" {
		cfg.caFile = os.Getenv("YDFI_TLS_CA_PATH")
	}
	if cfg.addr == "" {
		return nil, configErr("a server address is required (YDFI_SERVER_ADDR or WithServerAddr)")
	}
	name, err := verificationName(cfg.addr, cfg.serverName)
	if err != nil {
		return nil, err
	}

	c := &Client{certFile: cfg.certFile, keyFile: cfg.keyFile, logger: cfg.logger}
	if c.logger == nil {
		c.logger = slog.Default()
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: name}
	switch {
	case cfg.certFile != "":
		cert, err := readPair(cfg.certFile, cfg.keyFile)
		if err != nil {
			return nil, configErr("%v", err)
		}
		c.cert.Store(&cert)
		tlsCfg.GetClientCertificate = c.clientCertificate
	case cfg.certPEM != nil:
		cert, err := parsePair(cfg.certPEM, cfg.keyPEM)
		if err != nil {
			return nil, configErr("%v", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	default:
		return nil, configErr("a certificate and key are required (YDFI_TLS_CERT_PATH and YDFI_TLS_KEY_PATH, WithCertFiles or WithCert)")
	}
	caPEM := cfg.caPEM
	if cfg.caFile != "" {
		caPEM, err = readFile(cfg.caFile)
		if err != nil {
			return nil, configErr("%v", err)
		}
	}
	// The server's certificate comes from the deployment's own CA, so its
	// bundle is required: the system trust store would trust any server that
	// a public CA names for the host.
	if caPEM == nil {
		return nil, configErr("the deployment's CA bundle is required (YDFI_TLS_CA_PATH, WithCAFile or WithCA)")
	}
	if tlsCfg.RootCAs, err = certPool(caPEM); err != nil {
		return nil, configErr("%v", err)
	}
	// The bundle and the host name say only that the deployment's CA issued
	// some certificate for the host; the server's own certificate says that
	// it is a server.
	tlsCfg.VerifyConnection = verifyServerIdentity

	userAgent := cfg.userAgent
	if userAgent == "" {
		userAgent = "ydentifi-go/" + Version
	}
	dialOpts := append([]grpc.DialOption{}, cfg.dialOptions...)
	dialOpts = append(dialOpts,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithUserAgent(userAgent),
		// A service config from name resolution, such as a DNS TXT record,
		// could set a retry policy, and the client would send a call again on
		// its own. One given with grpc.WithDefaultServiceConfig still applies.
		grpc.WithDisableServiceConfig(),
	)
	if cfg.keepalive != nil {
		dialOpts = append(dialOpts, grpc.WithKeepaliveParams(*cfg.keepalive))
	}
	// The dns scheme makes the whole address a host and port, so an address
	// such as unix:443 never selects another gRPC resolver.
	c.conn, err = grpc.NewClient("dns:///"+cfg.addr, dialOpts...)
	if err != nil {
		return nil, configErr("%v", err)
	}
	c.svc = identitypb.NewIdentityServiceClient(c.conn)
	return c, nil
}

// verifyServerIdentity refuses a server whose certificate does not name it a
// Ydentifi server: exactly one URI SAN, spiffe://<trust domain>/server/<name>.
// It runs after the chain and the host name are verified.
func verifyServerIdentity(cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("ydentifi: the server presented no certificate")
	}
	uris := cs.PeerCertificates[0].URIs
	if len(uris) != 1 || !isServerID(uris[0]) {
		return errors.New("ydentifi: the server's certificate does not name a Ydentifi server (spiffe://<trust domain>/server/<name>)")
	}
	return nil
}

// isServerID reports whether u is spiffe://<trust domain>/server/<name>
// under the SPIFFE ID character rules, read from its escaped form: a trust
// domain of lowercase letters, digits, dots, dashes and underscores; a name
// of one segment of letters, digits, dots, dashes and underscores, other
// than "." and ".."; and nothing else, so a port, userinfo, a query, a
// fragment and percent-encoding are refused. Go's URL parser lowercases the
// scheme and drops an empty fragment before this reads it, so those two
// spellings are taken. Any trust domain is accepted: the CA bundle and the
// host name tell deployments apart.
func isServerID(u *url.URL) bool {
	rest, ok := strings.CutPrefix(u.String(), "spiffe://")
	if !ok {
		return false
	}
	trustDomain, name, ok := strings.Cut(rest, "/server/")
	return ok && spiffeChars(trustDomain, false) && spiffeChars(name, true) && name != "." && name != ".."
}

// spiffeChars reports whether s is non-empty and made of letters, digits,
// dots, dashes and underscores, its letters lowercase unless upper is set.
func spiffeChars(s string, upper bool) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		switch {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '.', c == '-', c == '_':
		case upper && 'A' <= c && c <= 'Z':
		default:
			return false
		}
	}
	return true
}

// Close closes the client's connection. Calls in flight, and calls made
// after Close, end with ErrCanceled. Close may be called more than once and
// from several goroutines: the connection is closed once, and every call
// returns the result of that close.
func (c *Client) Close() error {
	c.closeOnce.Do(func() { c.closeErr = c.conn.Close() })
	return c.closeErr
}

// clientCertificate is the tls.Config.GetClientCertificate hook of a client
// whose certificate comes from files. It reads the files at each TLS
// handshake. A pair that parses and is within its validity period replaces
// the certificate presented; otherwise the certificate in use is presented
// again, and the refusal is logged at Warn unless its reason is the one
// logged last. The files are named by their base names only.
func (c *Client) clientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cert, err := readPair(c.certFile, c.keyFile)
	if err == nil {
		now := time.Now()
		switch {
		case now.Before(cert.Leaf.NotBefore):
			err = fmt.Errorf("%s is not valid until %s", filepath.Base(c.certFile), cert.Leaf.NotBefore.UTC().Format(time.RFC3339))
		case now.After(cert.Leaf.NotAfter):
			err = fmt.Errorf("%s expired at %s", filepath.Base(c.certFile), cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
		}
	}
	if err != nil {
		reason := err.Error()
		if last := c.refused.Swap(&reason); last == nil || *last != reason {
			c.logger.Warn("certificate files not used; the certificate in use is presented again",
				"cert", filepath.Base(c.certFile), "key", filepath.Base(c.keyFile), "err", err)
		}
		return c.cert.Load(), nil
	}
	c.refused.Store(nil)
	c.cert.Store(&cert)
	return &cert, nil
}

// verificationName checks the server address and returns the name the
// server's certificate is verified against. The address is refused when it
// is empty or holds any of / ? # @ or whitespace. It is split into a host
// and a port in one of three shapes only: [v6]:port, host:port with one
// colon, or a host with no colon. A port is decimal digits with a value from
// 1 to 65535. A host that is an IP address requires serverName, which is
// then the name; for any other host the name is serverName when it is not
// empty, or else the host in lower case.
func verificationName(addr, serverName string) (string, error) {
	if addr == "" || strings.ContainsAny(addr, "/?#@") || strings.ContainsFunc(addr, unicode.IsSpace) {
		return "", configErr("the server address %q is not a host with an optional port", addr)
	}
	host := addr
	if strings.Contains(addr, ":") {
		h, port, err := net.SplitHostPort(addr)
		if err != nil {
			return "", configErr("the server address %q is not a host with an optional port: %v", addr, err)
		}
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return "", configErr("the server address %q has the port %q; a port is a number from 1 to 65535", addr, port)
		}
		if strings.HasPrefix(addr, "[") {
			if ip, err := netip.ParseAddr(h); err != nil || !ip.Is6() {
				return "", configErr("the server address %q holds %q in brackets, which is not an IPv6 address", addr, h)
			}
		}
		host = h
	}
	if host == "" || strings.ContainsAny(host, "[]") {
		return "", configErr("the server address %q names no host", addr)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		if serverName == "" {
			return "", configErr("the server address %q is an IP address; a server name is required (YDFI_SERVER_NAME or WithServerName)", addr)
		}
		return serverName, nil
	}
	if serverName != "" {
		return serverName, nil
	}
	return strings.ToLower(host), nil
}

// readPair reads a certificate file and a key file and parses them.
func readPair(certFile, keyFile string) (tls.Certificate, error) {
	certPEM, err := readFile(certFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := readFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	return parsePair(certPEM, keyPEM)
}

// readFile reads a regular file. A path that names anything else, such as
// a FIFO or a directory, is refused before it is opened, since the read of
// a FIFO waits for a writer. A symbolic link is followed. An error names
// the file by its base name only.
func readFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fileErr(path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("read %s: not a regular file", filepath.Base(path))
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fileErr(path, err)
	}
	return b, nil
}

// parsePair parses a PEM certificate chain and its key. tls.X509KeyPair
// parses only the leaf, and leaves it unset under GODEBUG=x509keypairleaf=0;
// every certificate of the chain is parsed here, because a chain the server
// cannot parse fails every handshake, and the leaf is set from the first,
// because its dates are read at each handshake.
func parsePair(certPEM, keyPEM []byte) (tls.Certificate, error) {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("parse the certificate and key: %w", err)
	}
	for i, der := range cert.Certificate {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("parse certificate %d of the chain: %w", i+1, err)
		}
		if i == 0 {
			cert.Leaf = parsed
		}
	}
	return cert, nil
}

// certPool returns a pool of the certificates of a PEM bundle. Every
// CERTIFICATE block must parse, whereas x509.CertPool.AppendCertsFromPEM
// skips a block that does not; blocks of other types are skipped. A bundle
// without a certificate is refused, so that a truncated file never selects
// the system trust store.
func certPool(bundle []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	found := false
	for {
		var block *pem.Block
		block, bundle = pem.Decode(bundle)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse the CA bundle: %w", err)
		}
		pool.AddCert(cert)
		found = true
	}
	if !found {
		return nil, errors.New("the CA bundle holds no certificate")
	}
	return pool, nil
}

// fileErr describes a file that cannot be read by its base name and the
// operating system's reason, so that no directory reaches an error or a log.
func fileErr(path string, err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return fmt.Errorf("read %s: %w", filepath.Base(path), err)
}
