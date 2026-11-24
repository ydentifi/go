package ydentifi

import (
	"fmt"
	"log/slog"
	"time"
)

// Formatting these result types with fmt, or recording one as a slog value
// of its own, redacts bearer secrets as lengths. Field access and
// encoding/json retain the original values so QR payloads can be delivered
// to the application interface; a slog handler that encodes a containing
// struct, slice or map with encoding/json therefore records them in full.

func redacted(n int) string { return fmt.Sprintf("<redacted %d bytes>", n) }

// String shows the invite with its token and QR payload redacted.
func (i EnrollmentInvite) String() string {
	return fmt.Sprintf("EnrollmentInvite{InviteToken: %s, QRPayload: %s, ExpiresAt: %s}",
		redacted(len(i.InviteToken)), redacted(len(i.QRPayload)), i.ExpiresAt.Format(time.RFC3339))
}

// Format prints String for every verb, so no verb reaches the raw fields.
func (i EnrollmentInvite) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(i.String())) }

// LogValue is what slog records for the invite.
func (i EnrollmentInvite) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("invite_token", redacted(len(i.InviteToken))),
		slog.String("qr_payload", redacted(len(i.QRPayload))),
		slog.Time("expires_at", i.ExpiresAt),
	)
}

// String shows the invite with its token and QR payload redacted.
func (i RecoveryInvite) String() string {
	return fmt.Sprintf("RecoveryInvite{InviteToken: %s, QRPayload: %s, ExpiresAt: %s, RevokedDeviceCount: %d}",
		redacted(len(i.InviteToken)), redacted(len(i.QRPayload)), i.ExpiresAt.Format(time.RFC3339),
		i.RevokedDeviceCount)
}

// Format prints String for every verb, so no verb reaches the raw fields.
func (i RecoveryInvite) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(i.String())) }

// LogValue is what slog records for the invite.
func (i RecoveryInvite) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("invite_token", redacted(len(i.InviteToken))),
		slog.String("qr_payload", redacted(len(i.QRPayload))),
		slog.Time("expires_at", i.ExpiresAt),
		slog.Any("revoked_device_count", i.RevokedDeviceCount),
	)
}

// String shows the enrolment with the seed, the URL that embeds it and the
// QR image that encodes it all redacted.
func (e TOTPEnrollment) String() string {
	return fmt.Sprintf("TOTPEnrollment{QRCodePNGBase64: %s, TOTPURL: %s, SecretBase32: %s}",
		redacted(len(e.QRCodePNGBase64)), redacted(len(e.TOTPURL)), redacted(len(e.SecretBase32)))
}

// Format prints String for every verb, so no verb reaches the raw fields.
func (e TOTPEnrollment) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(e.String())) }

// LogValue is what slog records for the enrolment.
func (e TOTPEnrollment) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("qr_code_png_base64", redacted(len(e.QRCodePNGBase64))),
		slog.String("totp_url", redacted(len(e.TOTPURL))),
		slog.String("secret_base32", redacted(len(e.SecretBase32))),
	)
}
