package ydentifi

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// SDK-072: formatting and logging a bearer-secret result print each secret
// field as its length only.
func TestSDK072_SecretsArePrintedAsTheirLengths(t *testing.T) {
	token, payload, seed := randomBytes(t, 32), randomBytes(t, 96), randomBytes(t, 20)
	secretB32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
	totpURL := "otpauth://totp/Ydentifi:u1?secret=" + secretB32 + "&issuer=Ydentifi"
	png := base64.StdEncoding.EncodeToString(append([]byte("\x89PNG"), randomBytes(t, 64)...))

	// Byte slices are also checked in their default decimal, space-separated
	// fmt representation.
	var secrets []string
	for _, b := range [][]byte{token, payload} {
		secrets = append(secrets,
			hex.EncodeToString(b), base64.StdEncoding.EncodeToString(b), string(b),
			strings.Trim(fmt.Sprint([]byte(b)), "[]"))
	}
	secrets = append(secrets, secretB32, totpURL, png)

	at := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	values := map[string]any{
		"EnrollmentInvite": EnrollmentInvite{InviteToken: token, QRPayload: payload, ExpiresAt: at},
		"RecoveryInvite":   RecoveryInvite{InviteToken: token, QRPayload: payload, ExpiresAt: at, RevokedDeviceCount: 2},
		"TOTPEnrollment":   TOTPEnrollment{QRCodePNGBase64: png, TOTPURL: totpURL, SecretBase32: secretB32},
	}
	// The length each secret field prints as.
	lengths := map[string][]int{
		"EnrollmentInvite": {len(token), len(payload)},
		"RecoveryInvite":   {len(token), len(payload)},
		"TOTPEnrollment":   {len(png), len(totpURL), len(secretB32)},
	}
	for name, v := range values {
		var renderings []string
		for _, x := range []any{v, pointerTo(v), struct{ Result any }{v}} {
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%q"} {
				renderings = append(renderings, fmt.Sprintf(verb, x))
			}
			renderings = append(renderings, fmt.Sprint(x), fmt.Sprintln(x))
		}

		var buf bytes.Buffer
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("issued", "result", v)
		slog.New(slog.NewTextHandler(&buf, nil)).Info("issued", "result", v)
		slog.New(slog.NewJSONHandler(&buf, nil)).Info("issued", slog.Any("result", pointerTo(v)))
		log.New(&buf, "", 0).Printf("issued %v", v)
		renderings = append(renderings, buf.String())

		for _, out := range renderings {
			if !strings.Contains(out, "redacted") {
				t.Fatalf("%s: a rendering shows no redaction: %s", name, out)
			}
			for _, n := range lengths[name] {
				if !strings.Contains(out, fmt.Sprintf("<redacted %d bytes>", n)) {
					t.Fatalf("%s: a rendering does not print a secret of %d bytes as its length: %s", name, n, out)
				}
			}
			for _, s := range secrets {
				if slice, ok := sixteenFrom(out, s); ok {
					t.Fatalf("%s: a rendering carries a secret (%q): %s", name, slice, out)
				}
			}
		}
	}
}

// Redaction applies to formatting; direct field access retains secrets.
func TestSecretBearingResultsKeepTheirFields(t *testing.T) {
	inv := EnrollmentInvite{InviteToken: []byte("tok"), QRPayload: []byte("qr")}
	if string(inv.InviteToken) != "tok" || string(inv.QRPayload) != "qr" {
		t.Fatal("the invite's fields changed")
	}
	if got := inv.String(); !strings.Contains(got, "<redacted 3 bytes>") {
		t.Fatalf("String() = %q, want the token's length", got)
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func pointerTo(v any) any {
	switch x := v.(type) {
	case EnrollmentInvite:
		return &x
	case RecoveryInvite:
		return &x
	case TOTPEnrollment:
		return &x
	}
	panic(fmt.Sprintf("no pointer case for %T", v))
}

// sixteenFrom reports the first 16-character slice of secret that out holds.
func sixteenFrom(out, secret string) (string, bool) {
	for i := 0; i+16 <= len(secret); i++ {
		if strings.Contains(out, secret[i:i+16]) {
			return secret[i : i+16], true
		}
	}
	return "", false
}
