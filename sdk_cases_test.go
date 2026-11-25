package ydentifi

// The client's behaviour that needs no server: configuration, the address
// rule, the closing of a client that has not connected, local refusals and
// enum names.

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	identitypb "github.com/ydentifi/go/internal/ydfi-proto-go/identity"
	"google.golang.org/grpc/connectivity"
)

// closedAddr names a port nothing listens on: a call that reached the
// network would end with ErrUnavailable.
const closedAddr = "localhost:1"

// localSlack is how long a refusal made before any request may take.
const localSlack = 100 * time.Millisecond

// wantConfigErr fails unless New returned no client and an error that
// matches ErrConfiguration.
func wantConfigErr(t *testing.T, what string, c *Client, err error) {
	t.Helper()
	if c != nil {
		if cerr := c.Close(); cerr != nil {
			t.Error(cerr)
		}
	}
	if c != nil || !errors.Is(err, ErrConfiguration) {
		t.Fatalf("%s: client built %v, %v; want ErrConfiguration and no client", what, c != nil, err)
	}
}

// SDK-005: an address, a certificate and a key are required. Each missing
// one is refused by New, which returns no client and so opens no
// connection.
func TestSDK005_MissingRequiredMaterial(t *testing.T) {
	certPEM, keyPEM := validPair(t, "rp")
	certFile, keyFile := writePair(t, t.TempDir(), certPEM, keyPEM)
	for _, tc := range []struct {
		name string
		env  map[string]string
		opts []Option
	}{
		{"no address, the pair as options", nil, []Option{WithCert(certPEM, keyPEM)}},
		{"no address, the pair from the environment", map[string]string{"YDFI_TLS_CERT_PATH": certFile, "YDFI_TLS_KEY_PATH": keyFile}, nil},
		{"no certificate, as options", nil, []Option{WithServerAddr(closedAddr)}},
		{"no certificate, from the environment", map[string]string{"YDFI_SERVER_ADDR": closedAddr, "YDFI_TLS_KEY_PATH": keyFile}, nil},
		{"no key, from the environment", map[string]string{"YDFI_SERVER_ADDR": closedAddr, "YDFI_TLS_CERT_PATH": certFile}, nil},
		{"no CA bundle", nil, []Option{WithServerAddr(closedAddr), WithCert(certPEM, keyPEM)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateFromEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			c, err := New(tc.opts...)
			wantConfigErr(t, tc.name, c, err)
		})
	}
}

// SDK-006: half a pair is refused: a certificate file without a key file,
// and a certificate as bytes without a key.
func TestSDK006_HalfAPair(t *testing.T) {
	isolateFromEnv(t)
	certPEM, keyPEM := validPair(t, "rp")
	certFile, _ := writePair(t, t.TempDir(), certPEM, keyPEM)
	for name, opt := range map[string]Option{
		"a certificate file without a key file": WithCertFiles(certFile, ""),
		"a certificate as bytes without a key":  WithCert(certPEM, nil),
	} {
		t.Run(name, func(t *testing.T) {
			c, err := New(WithServerAddr(closedAddr), opt)
			wantConfigErr(t, name, c, err)
		})
	}
}

// SDK-009: material that does not parse is refused by New.
func TestSDK009_MaterialThatDoesNotParse(t *testing.T) {
	isolateFromEnv(t)
	m := newTLSMaterial(t)
	chain := append(append([]byte{}, m.certPEM...), corruptCertBlock...)
	for name, opts := range map[string][]Option{
		"a certificate that is not PEM":                   {WithCert([]byte("not a pem"), m.keyPEM)},
		"a key that is not PEM":                           {WithCert(m.certPEM, []byte("not a pem"))},
		"a key that is not the certificate's":             {WithCert(m.certPEM, m.otherKeyPEM)},
		"a chain whose second certificate does not parse": {WithCert(chain, m.keyPEM)},
		"a CA bundle that does not parse":                 {WithCert(m.certPEM, m.keyPEM), WithCA(append(append([]byte{}, corruptCertBlock...), m.caPEM...))},
		"a CA bundle that is empty":                       {WithCert(m.certPEM, m.keyPEM), WithCA([]byte{})},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := New(append(opts, WithServerAddr(closedAddr))...)
			wantConfigErr(t, name, c, err)
		})
	}
}

// SDK-017: an address option given as the empty string is refused, though
// YDFI_SERVER_ADDR names a server: an empty option is a mistake, not a
// request for the environment's address.
func TestSDK017_AnEmptyAddressOptionIsRefused(t *testing.T) {
	isolateFromEnv(t)
	t.Setenv("YDFI_SERVER_ADDR", closedAddr)
	certPEM, keyPEM := validPair(t, "rp")
	c, err := New(WithServerAddr(""), WithCert(certPEM, keyPEM), WithCA(certPEM))
	wantConfigErr(t, "an empty address option", c, err)
	if !strings.Contains(err.Error(), "WithServerAddr was given an empty address") {
		t.Fatalf("New: %v; want the empty option named", err)
	}
}

// SDK-010: a bare host with no port, which the address rule admits, builds
// a client whose verification name is the host. No call is made.
func TestSDK010_ABareHostWithNoPort(t *testing.T) {
	isolateFromEnv(t)
	certPEM, keyPEM := validPair(t, "rp")
	c, err := New(WithServerAddr("localhost"), WithCert(certPEM, keyPEM), WithCA(certPEM))
	if err != nil {
		t.Fatalf("New: %v; want a client", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if name, err := verificationName("localhost", ""); err != nil || name != "localhost" {
		t.Fatalf("the verification name of localhost: %q, %v; want localhost", name, err)
	}
}

// SDK-011: an address that is not a bare host and port is refused.
func TestSDK011_AnAddressThatIsNotABareHostAndPort(t *testing.T) {
	isolateFromEnv(t)
	certPEM, keyPEM := validPair(t, "rp")
	for _, addr := range []string{"dns:///localhost:443", "localhost:443/x", "::1:443", "[localhost]:443"} {
		t.Run(addr, func(t *testing.T) {
			c, err := New(WithServerAddr(addr), WithCert(certPEM, keyPEM), WithCA(certPEM))
			wantConfigErr(t, addr, c, err)
		})
	}
}

// SDK-012: an address with no host is refused, with a verification name
// and without one.
func TestSDK012_NoHost(t *testing.T) {
	isolateFromEnv(t)
	certPEM, keyPEM := validPair(t, "rp")
	for _, name := range []string{"", "localhost"} {
		c, err := New(WithServerAddr(":443"), WithServerName(name), WithCert(certPEM, keyPEM), WithCA(certPEM))
		wantConfigErr(t, `":443" with the verification name "`+name+`"`, c, err)
	}
}

// SDK-013: the ports 1 and 65535 are accepted; 0, 65536 and abc are
// refused, with a verification name and without one.
func TestSDK013_ThePortsBounds(t *testing.T) {
	isolateFromEnv(t)
	certPEM, keyPEM := validPair(t, "rp")
	for _, name := range []string{"", "localhost"} {
		for _, port := range []string{"1", "65535"} {
			c, err := New(WithServerAddr("localhost:"+port), WithServerName(name), WithCert(certPEM, keyPEM), WithCA(certPEM))
			if err != nil {
				t.Fatalf("port %s, verification name %q: %v; want a client", port, name, err)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
		}
		for _, port := range []string{"0", "65536", "abc"} {
			c, err := New(WithServerAddr("localhost:"+port), WithServerName(name), WithCert(certPEM, keyPEM), WithCA(certPEM))
			wantConfigErr(t, "port "+port+", verification name "+name, c, err)
		}
	}
}

// SDK-043: Close called by 8 goroutines at once, then once more, returns
// the same result every time. The client has made no connection, so no
// server is needed.
func TestSDK043_ClosingAnIdleClientFromManyCallers(t *testing.T) {
	isolateFromEnv(t)
	certPEM, keyPEM := validPair(t, "rp")
	c, err := New(WithServerAddr(closedAddr), WithCert(certPEM, keyPEM), WithCA(certPEM))
	if err != nil {
		t.Fatal(err)
	}
	results := make([]error, 9)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = c.Close()
		}()
	}
	wg.Wait()
	results[8] = c.Close()
	for i, err := range results {
		if err != nil {
			t.Errorf("Close %d: %v; want nil, the result of the first Close", i+1, err)
		}
	}
}

// SDK-061: a TTL that the uint32 field ttl_seconds cannot carry, below
// zero or of 2^32 seconds or more, is refused at once by each method that
// takes one, before any request is sent. The client's address names a
// closed port, so an attempt to send would end with ErrUnavailable; the
// connection stays idle throughout.
func TestSDK061_ATTLTheWireTypeCannotHold(t *testing.T) {
	c := newTestClient(t)
	ctx := context.Background()
	const user = "00000000000000000000000000000000000000000000000000000000000000ff"
	calls := map[string]func(ttl time.Duration) error{
		"IssueAuthChallenge": func(ttl time.Duration) error {
			_, err := c.IssueAuthChallenge(ctx, IssueAuthChallengeRequest{OpaqueID: user, TTL: ttl})
			return err
		},
		"IssueEnrollmentInvite": func(ttl time.Duration) error {
			_, err := c.IssueEnrollmentInvite(ctx, IssueEnrollmentInviteRequest{OpaqueID: user, TTL: ttl})
			return err
		},
		"IssueRecoveryInvite": func(ttl time.Duration) error {
			_, err := c.IssueRecoveryInvite(ctx, IssueRecoveryInviteRequest{OpaqueID: user, TTL: ttl})
			return err
		},
	}
	// -1ns is the TTL below zero nearest to zero, which whole seconds would
	// carry as 0.
	for _, ttl := range []time.Duration{-time.Nanosecond, -time.Second, (1 << 32) * time.Second} {
		for name, call := range calls {
			start := time.Now()
			err := call(ttl)
			took := time.Since(start)
			var se *StatusError
			if !errors.Is(err, ErrInvalidArgument) || errors.As(err, &se) || !strings.Contains(err.Error(), "TTL") {
				t.Errorf("%s with TTL %v: %v; want the local refusal, which carries no reason and no field", name, ttl, err)
			}
			if took > localSlack {
				t.Errorf("%s with TTL %v: refused after %v; want at once, within %v", name, ttl, took, localSlack)
			}
		}
	}
	if state := c.conn.GetState(); state != connectivity.Idle {
		t.Fatalf("the connection is %v after the refusals; want Idle: no connection attempted", state)
	}
}

// SDK-061: the other number fields cannot hold such a value in Go. The
// count and the match code are uint32 in the SDK's own signatures, as the
// request fields are on the wire, so the compiler refuses a negative or a
// 33-bit value. The TTL is a time.Duration, checked by the case above.
func TestSDK061_TheOtherNumbersAreUnsigned32Bit(t *testing.T) {
	field := func(v any, name string) reflect.Type {
		f, ok := reflect.TypeOf(v).Elem().FieldByName(name)
		if !ok {
			t.Fatalf("%T has no field %s", v, name)
		}
		return f.Type
	}
	for name, typ := range map[string]reflect.Type{
		"the count of Client.BulkCreateUsers":       reflect.TypeOf((*Client).BulkCreateUsers).In(2),
		"IssueAuthChallengeRequest.MatchCode":       field((*IssueAuthChallengeRequest)(nil), "MatchCode"),
		"the wire's BulkCreateUsersRequest.Count":   field((*identitypb.BulkCreateUsersRequest)(nil), "Count"),
		"the wire's IssueAuthChallengeRequest.TTL":  field((*identitypb.IssueAuthChallengeRequest)(nil), "TtlSeconds"),
		"the wire's IssueAuthChallengeRequest.Code": field((*identitypb.IssueAuthChallengeRequest)(nil), "MatchCode"),
	} {
		if typ.Kind() != reflect.Uint32 {
			t.Errorf("%s is %v; want uint32", name, typ)
		}
	}
	if typ := field((*IssueAuthChallengeRequest)(nil), "TTL"); typ != reflect.TypeOf(time.Duration(0)) {
		t.Errorf("IssueAuthChallengeRequest.TTL is %v; want time.Duration", typ)
	}
}

// SDK-071: every value of every enum prints its protocol name without the
// enum's prefix, as the other SDKs print it, and a value with no name, the
// one past the last among them, prints UNKNOWN_<n>. The names are read
// from the generated protocol code. KeyAlgorithm is not part of this SDK's
// surface: no result carries one.
func TestSDK071_EnumNames(t *testing.T) {
	for _, e := range []struct {
		prefix string
		names  map[int32]string
		str    func(int32) string
	}{
		{"USER_STATUS_", identitypb.UserStatus_name, func(v int32) string { return UserStatus(v).String() }},
		{"DEVICE_PLATFORM_", identitypb.DevicePlatform_name, func(v int32) string { return DevicePlatform(v).String() }},
		{"DEVICE_STATUS_", identitypb.DeviceStatus_name, func(v int32) string { return DeviceStatus(v).String() }},
		{"AUTH_CHALLENGE_STATUS_", identitypb.AuthChallengeStatus_name, func(v int32) string { return ChallengeStatus(v).String() }},
		{"AUTH_CHALLENGE_EXPRESSION_", identitypb.AuthChallengeExpression_name, func(v int32) string { return ChallengeExpression(v).String() }},
		{"DECLINE_REASON_", identitypb.DeclineReason_name, func(v int32) string { return DeclineReason(v).String() }},
		{"VERIFICATION_FAILURE_", identitypb.VerificationFailure_name, func(v int32) string { return VerificationFailure(v).String() }},
		{"AUTH_STRENGTH_", identitypb.AuthStrength_name, func(v int32) string { return AuthStrength(v).String() }},
		{"LOCATION_BUCKET_", identitypb.LocationBucket_name, func(v int32) string { return LocationBucket(v).String() }},
		{"LOCATION_ACCURACY_", identitypb.LocationAccuracy_name, func(v int32) string { return LocationAccuracy(v).String() }},
		{"LOCATION_ENFORCEMENT_", identitypb.LocationEnforcement_name, func(v int32) string { return LocationEnforcement(v).String() }},
		{"ERROR_REASON_", identitypb.ErrorReason_name, func(v int32) string { return ErrorReason(v).String() }},
	} {
		last := int32(0)
		for v := range e.names {
			last = max(last, v)
		}
		for v := int32(0); v <= last+1; v++ {
			want := "UNKNOWN_" + strconv.Itoa(int(v))
			if name, ok := e.names[v]; ok {
				want = strings.TrimPrefix(name, e.prefix)
			}
			if got := e.str(v); got != want {
				t.Errorf("%s%d prints %q; want %q", e.prefix, v, got, want)
			}
		}
	}
}
