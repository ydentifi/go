package ydentifi

import (
	"context"
	"time"

	identitypb "github.com/ydentifi/go/internal/ydfi-proto-go/identity"
)

// IssueEnrollmentInviteRequest holds the parameters of IssueEnrollmentInvite.
type IssueEnrollmentInviteRequest struct {
	// OpaqueID names the user.
	OpaqueID string
	// TTL is how long the invite can be scanned, from 60 to 600 seconds; it
	// is sent in whole seconds. Zero selects 300 seconds. A TTL below zero,
	// or of 2^32 seconds or more, is refused before any request is sent,
	// with an error that matches ErrInvalidArgument.
	TTL time.Duration
	// Context is optional, up to 256 bytes, and is kept with the invite.
	// The phone does not show it, and the enrolment does not sign it.
	Context []byte
}

// IssueEnrollmentInvite issues an invite that the user scans with the
// Ydentifi app to enrol a phone.
func (c *Client) IssueEnrollmentInvite(ctx context.Context, req IssueEnrollmentInviteRequest) (*EnrollmentInvite, error) {
	if err := checkUTF8("OpaqueID", req.OpaqueID); err != nil {
		return nil, err
	}
	ttl, err := ttlSeconds(req.TTL)
	if err != nil {
		return nil, err
	}
	resp, err := c.svc.IssueEnrollmentInvite(ctx, &identitypb.IssueEnrollmentInviteRequest{
		OpaqueId:   req.OpaqueID,
		TtlSeconds: ttl,
		Context:    req.Context,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return convertEnrollmentInvite(resp)
}

// IssueRecoveryInviteRequest holds the parameters of IssueRecoveryInvite.
type IssueRecoveryInviteRequest struct {
	// OpaqueID names the user.
	OpaqueID string
	// TTL is how long the invite can be scanned, from 60 to 600 seconds; it
	// is sent in whole seconds. Zero selects 300 seconds. A TTL below zero,
	// or of 2^32 seconds or more, is refused before any request is sent,
	// with an error that matches ErrInvalidArgument.
	TTL time.Duration
	// Context is optional, up to 256 bytes, and is kept with the invite.
	// The phone does not show it, and the enrolment does not sign it.
	Context []byte
}

// IssueRecoveryInvite revokes all of the user's active devices and issues
// an invite to enrol a new phone. The server takes the call as the
// authority, so the relying party authenticates the user out of band
// first. The revoked phones keep the TOTP secret until
// IssueUserTOTPEnrollment replaces it.
func (c *Client) IssueRecoveryInvite(ctx context.Context, req IssueRecoveryInviteRequest) (*RecoveryInvite, error) {
	if err := checkUTF8("OpaqueID", req.OpaqueID); err != nil {
		return nil, err
	}
	ttl, err := ttlSeconds(req.TTL)
	if err != nil {
		return nil, err
	}
	resp, err := c.svc.IssueRecoveryInvite(ctx, &identitypb.IssueRecoveryInviteRequest{
		OpaqueId:   req.OpaqueID,
		TtlSeconds: ttl,
		Context:    req.Context,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return convertRecoveryInvite(resp)
}
