package ydentifi

import (
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// config is the configuration the options build. New fills what the options
// leave unset from the environment.
type config struct {
	addr, serverName  string
	certFile, keyFile string
	certPEM, keyPEM   []byte
	caFile            string
	caPEM             []byte
	userAgent         string
	logger            *slog.Logger
	keepalive         *keepalive.ClientParameters
	dialOptions       []grpc.DialOption
}

// Option configures a Client. Options are applied in order, and a later
// option replaces what an earlier one set. The conflicts that New refuses
// are a certificate given both by WithCertFiles and by WithCert, and a CA
// bundle given both by WithCAFile and by WithCA.
type Option func(*config)

// WithServerAddr sets the server's address: a host with an optional port,
// with an IPv6 address in brackets, such as auth.example.com:443 or
// [2001:db8::1]:443. It takes precedence over YDFI_SERVER_ADDR.
func WithServerAddr(addr string) Option {
	return func(c *config) { c.addr = addr }
}

// WithServerName sets the name that the server's certificate is verified
// against, which is also sent as the TLS server name. It is required when
// the address is an IP address. Without it, the name is the address's host
// in lower case. It takes precedence over YDFI_SERVER_NAME.
func WithServerName(name string) Option {
	return func(c *config) { c.serverName = name }
}

// WithCertFiles sets the files of the relying party's certificate and key,
// in PEM. New reads them, and the client reads them again at each new
// connection: a valid pair written to the files is presented from the next
// connection onwards. A pair that cannot be read, does not parse or is
// outside its validity period is not used, and the refusal is logged. Each
// file is to be replaced atomically, by a rename. WithCertFiles takes
// precedence over YDFI_TLS_CERT_PATH and YDFI_TLS_KEY_PATH.
func WithCertFiles(certFile, keyFile string) Option {
	return func(c *config) { c.certFile, c.keyFile = certFile, keyFile }
}

// WithCert sets the relying party's certificate and key as PEM bytes, which
// are used for the client's lifetime. The slices are not copied and are not
// to be modified after the call. WithCert takes precedence over
// YDFI_TLS_CERT_PATH and YDFI_TLS_KEY_PATH.
func WithCert(certPEM, keyPEM []byte) Option {
	return func(c *config) { c.certPEM, c.keyPEM = certPEM, keyPEM }
}

// WithCAFile sets the file of the deployment's CA bundle that verifies the
// server, in PEM. It takes precedence over YDFI_TLS_CA_PATH, and New refuses
// it together with WithCA. A CA bundle is required: from WithCAFile, WithCA
// or YDFI_TLS_CA_PATH.
func WithCAFile(caFile string) Option {
	return func(c *config) { c.caFile = caFile }
}

// WithCA sets the deployment's CA bundle that verifies the server, as PEM
// bytes. It takes
// precedence over YDFI_TLS_CA_PATH, and New refuses it together with
// WithCAFile. A bundle that holds no certificate is refused.
func WithCA(caPEM []byte) Option {
	return func(c *config) { c.caPEM = caPEM }
}

// WithUserAgent sets the gRPC User-Agent. The empty string selects the
// default, "ydentifi-go/" followed by Version.
func WithUserAgent(userAgent string) Option {
	return func(c *config) { c.userAgent = userAgent }
}

// WithKeepalive sets the client's gRPC keepalive parameters, for a
// connection that a NAT or a load balancer may otherwise drop while it is
// idle.
func WithKeepalive(params keepalive.ClientParameters) Option {
	return func(c *config) { c.keepalive = &params }
}

// WithDialOptions sets additional gRPC dial options. The client's TLS
// credentials, user agent and keepalive parameters are applied after them
// and take precedence.
func WithDialOptions(opts ...grpc.DialOption) Option {
	return func(c *config) { c.dialOptions = opts }
}

// WithLogger sets the logger to which the client reports certificate files
// that it does not use. The default, and the logger a nil value selects, is
// slog.Default().
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}
