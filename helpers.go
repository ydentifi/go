package ydentifi

import (
	"fmt"
	"time"

	identitypb "github.com/ydentifi/go/internal/ydfi-proto-go/identity"
)

// times parses the RFC 3339 times of one answer of the server and keeps
// the first that does not parse.
type times struct{ err error }

// parse returns the time s holds; an empty string is the zero time. A
// string that does not parse is recorded as an error wrapping
// ErrMalformedResponse, and the zero time is returned.
func (ts *times) parse(field, s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil && ts.err == nil {
		ts.err = fmt.Errorf("%w: %s: %w", ErrMalformedResponse, field, err)
	}
	return t
}

func convertUser(u *identitypb.GetUserResponse) (*User, error) {
	var ts times
	out := &User{
		OpaqueID:            u.OpaqueId,
		Status:              UserStatus(u.Status),
		CreatedAt:           ts.parse("created_at", u.CreatedAt),
		LastAuthenticatedAt: ts.parse("last_authenticated_at", u.LastAuthenticatedAt),
		LastActivityAt:      ts.parse("last_activity_at", u.LastActivityAt),
		TOTPLocked:          u.TotpLocked,
	}
	if ts.err != nil {
		return nil, ts.err
	}
	return out, nil
}

func convertDevice(d *identitypb.DeviceSummary) (*Device, error) {
	var ts times
	out := &Device{
		DeviceID:            d.DeviceId,
		PermanentID:         d.PermanentId,
		Platform:            DevicePlatform(d.Platform),
		Status:              DeviceStatus(d.Status),
		CreatedAt:           ts.parse("created_at", d.CreatedAt),
		LastAuthenticatedAt: ts.parse("last_authenticated_at", d.LastAuthenticatedAt),
		Name:                d.Name,
		Model:               d.DeviceModel,
	}
	if ts.err != nil {
		return nil, ts.err
	}
	return out, nil
}

func convertChallengeFrame(f *identitypb.AwaitChallengeFrame) (*ChallengeResult, error) {
	var ts times
	r := &ChallengeResult{
		Status:              ChallengeStatus(f.Status),
		Expression:          ChallengeExpression(f.Expression),
		Signature:           f.Signature,
		DeclineReason:       DeclineReason(f.DeclineReason),
		VerificationFailure: VerificationFailure(f.VerificationFailure),
		EmittedAt:           ts.parse("emitted_at", f.EmittedAt),
		AuthStrength:        AuthStrength(f.AuthStrength),
	}
	if lr := f.LocationResult; lr != nil {
		r.LocationResult = &LocationResult{
			Bucket:   LocationBucket(lr.Bucket),
			Accuracy: LocationAccuracy(lr.Accuracy),
		}
	}
	if ts.err != nil {
		return nil, ts.err
	}
	return r, nil
}

func convertActiveChallenge(s *identitypb.ActiveChallengeSummary) (*ActiveChallenge, error) {
	var ts times
	a := &ActiveChallenge{
		ChallengeID: s.ChallengeId,
		Status:      ChallengeStatus(s.Status),
		Context:     s.Context,
		IssuedAt:    ts.parse("issued_at", s.IssuedAt),
		ExpiresAt:   ts.parse("expires_at", s.ExpiresAt),
		DeliveredAt: ts.parse("delivered_at", s.DeliveredAt),
	}
	if lc := s.LocationConstraint; lc != nil {
		a.LocationConstraint = &LocationConstraint{
			Latitude:     lc.Latitude,
			Longitude:    lc.Longitude,
			RadiusMeters: lc.RadiusM,
			Enforcement:  LocationEnforcement(lc.Enforcement),
		}
	}
	if ts.err != nil {
		return nil, ts.err
	}
	return a, nil
}

func convertChallenge(r *identitypb.IssueAuthChallengeResponse) (*Challenge, error) {
	var ts times
	out := &Challenge{
		ChallengeID: r.ChallengeId,
		QREncoded:   r.QrEncoded,
		ExpiresAt:   ts.parse("expires_at", r.ExpiresAt),
	}
	if ts.err != nil {
		return nil, ts.err
	}
	return out, nil
}

func convertEnrollmentInvite(r *identitypb.IssueEnrollmentInviteResponse) (*EnrollmentInvite, error) {
	var ts times
	out := &EnrollmentInvite{
		InviteToken: r.InviteToken,
		QRPayload:   r.QrPayload,
		ExpiresAt:   ts.parse("expires_at", r.ExpiresAt),
	}
	if ts.err != nil {
		return nil, ts.err
	}
	return out, nil
}

func convertRecoveryInvite(r *identitypb.IssueRecoveryInviteResponse) (*RecoveryInvite, error) {
	var ts times
	out := &RecoveryInvite{
		InviteToken:        r.InviteToken,
		QRPayload:          r.QrPayload,
		ExpiresAt:          ts.parse("expires_at", r.ExpiresAt),
		RevokedDeviceCount: r.RevokedDeviceCount,
	}
	if ts.err != nil {
		return nil, ts.err
	}
	return out, nil
}

// convertAll converts each message of a list; the first that cannot be
// read ends it.
func convertAll[M, T any](in []M, convert func(M) (T, error)) ([]T, error) {
	out := make([]T, 0, len(in))
	for _, m := range in {
		v, err := convert(m)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
