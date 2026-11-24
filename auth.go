package ydentifi

import (
	"context"
	"io"
	"iter"
	"time"

	identitypb "github.com/ydentifi/go/internal/ydfi-proto-go/identity"
)

// IssueAuthChallengeRequest holds the parameters of IssueAuthChallenge.
type IssueAuthChallengeRequest struct {
	// OpaqueID names the user.
	OpaqueID string
	// TTL is how long the challenge stays open, from 30 to 300 seconds; it
	// is sent in whole seconds. Zero selects 60 seconds. A TTL below zero,
	// or of 2^32 seconds or more, is refused before any request is sent,
	// with an error that matches ErrInvalidArgument.
	TTL time.Duration
	// Context is the text the phone shows and the user signs: 16 to 256
	// bytes of UTF-8 in NFC. The README lists the characters the server
	// refuses.
	Context []byte
	// LocationConstraint is an optional geofence; nil sets none.
	LocationConstraint *LocationConstraint
	// MatchCode enables number matching with a value from 10 to 99; zero
	// disables it.
	MatchCode uint32
	// MinStrength is the weakest unlock an approval may use.
	// AuthStrengthUnspecified is refused.
	MinStrength AuthStrength
	// ChallengeID is an optional ID for the challenge, a 26-character
	// uppercase ULID. A repeated request with the same ID returns
	// ErrAlreadyExists, and a different request with it returns
	// ErrInvalidArgument. When it is empty, the server creates the ID.
	ChallengeID string
}

// IssueAuthChallenge issues a challenge to the user's phones.
// Challenge.QREncoded is the challenge's URL, to be rendered unchanged as a
// QR code.
func (c *Client) IssueAuthChallenge(ctx context.Context, req IssueAuthChallengeRequest) (*Challenge, error) {
	if err := checkUTF8("OpaqueID", req.OpaqueID); err != nil {
		return nil, err
	}
	if err := checkUTF8("ChallengeID", req.ChallengeID); err != nil {
		return nil, err
	}
	ttl, err := ttlSeconds(req.TTL)
	if err != nil {
		return nil, err
	}
	pb := &identitypb.IssueAuthChallengeRequest{
		OpaqueId:    req.OpaqueID,
		TtlSeconds:  ttl,
		Context:     req.Context,
		MatchCode:   req.MatchCode,
		MinStrength: identitypb.AuthStrength(req.MinStrength),
		ChallengeId: req.ChallengeID,
	}
	if lc := req.LocationConstraint; lc != nil {
		pb.LocationConstraint = &identitypb.LocationConstraint{
			Latitude:    lc.Latitude,
			Longitude:   lc.Longitude,
			RadiusM:     lc.RadiusMeters,
			Enforcement: identitypb.LocationEnforcement(lc.Enforcement),
		}
	}
	resp, err := c.svc.IssueAuthChallenge(ctx, pb)
	if err != nil {
		return nil, mapErr(err)
	}
	return convertChallenge(resp)
}

// AwaitChallenge yields the frames of a challenge's wait stream. The first
// frame is the challenge's current state, which may already be its outcome;
// the server ends the stream after the first frame whose status
// IsTerminal. The server holds the stream open until the challenge is
// answered, or until 5 seconds after it expires, and then sends Expired.
//
// Each range over the returned iterator issues a new call. Leaving the loop
// ends the call. An error ends the iteration after it is yielded.
func (c *Client) AwaitChallenge(ctx context.Context, challengeID string) iter.Seq2[*ChallengeResult, error] {
	return func(yield func(*ChallengeResult, error) bool) {
		if err := checkUTF8("challengeID", challengeID); err != nil {
			yield(nil, err)
			return
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stream, err := c.svc.AwaitChallenge(ctx, &identitypb.AwaitChallengeRequest{ChallengeId: challengeID})
		if err != nil {
			yield(nil, mapErr(err))
			return
		}
		for {
			frame, err := stream.Recv()
			if err == io.EOF {
				return
			}
			if err != nil {
				yield(nil, mapErr(err))
				return
			}
			r, err := convertChallengeFrame(frame)
			if err != nil {
				yield(nil, err)
				return
			}
			if !yield(r, nil) {
				return
			}
		}
	}
}

// IsTerminal reports whether the status ends the challenge: Approved,
// Denied, Rejected, Expired, Superseded or Dismissed.
func (s ChallengeStatus) IsTerminal() bool {
	switch s {
	case ChallengeStatusApproved,
		ChallengeStatusDenied,
		ChallengeStatusRejected,
		ChallengeStatusExpired,
		ChallengeStatusSuperseded,
		ChallengeStatusDismissed:
		return true
	}
	return false
}

// ListActiveChallenges returns a user's open challenges, those pending or
// delivered.
func (c *Client) ListActiveChallenges(ctx context.Context, opaqueID string) ([]*ActiveChallenge, error) {
	if err := checkUTF8("opaqueID", opaqueID); err != nil {
		return nil, err
	}
	resp, err := c.svc.ListActiveChallenges(ctx, &identitypb.ListActiveChallengesRequest{OpaqueId: opaqueID})
	if err != nil {
		return nil, mapErr(err)
	}
	return convertAll(resp.Challenges, convertActiveChallenge)
}

// IssueUserTOTPEnrollment returns the user's TOTP secret when reuseExisting
// is true, or replaces it with a new one when it is false. A new secret is
// sent to every device the user still has, and lifts a TOTP lock.
func (c *Client) IssueUserTOTPEnrollment(ctx context.Context, opaqueID string, reuseExisting bool) (*TOTPEnrollment, error) {
	if err := checkUTF8("opaqueID", opaqueID); err != nil {
		return nil, err
	}
	resp, err := c.svc.IssueUserTotpEnrollment(ctx, &identitypb.IssueUserTotpEnrollmentRequest{
		OpaqueId:      opaqueID,
		ReuseExisting: reuseExisting,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return &TOTPEnrollment{
		QRCodePNGBase64: resp.QrCodePngBase64,
		TOTPURL:         resp.TotpUrl,
		SecretBase32:    resp.SecretBase32,
	}, nil
}

// VerifyUserTOTP checks a six-digit TOTP code. It returns true for a valid
// code, and false without an error for an incorrect code or a code already
// accepted once.
func (c *Client) VerifyUserTOTP(ctx context.Context, opaqueID, code string) (bool, error) {
	if err := checkUTF8("opaqueID", opaqueID); err != nil {
		return false, err
	}
	if err := checkUTF8("code", code); err != nil {
		return false, err
	}
	resp, err := c.svc.VerifyUserTotp(ctx, &identitypb.VerifyUserTotpRequest{OpaqueId: opaqueID, TotpCode: code})
	if err != nil {
		return false, mapErr(err)
	}
	return resp.Valid, nil
}
