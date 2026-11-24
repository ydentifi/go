package ydentifi

import (
	"context"
	"io"
	"iter"

	identitypb "github.com/ydentifi/go/internal/ydfi-proto-go/identity"
)

// CreateUser creates an anonymous user for the calling relying party and
// returns its opaque ID, 64 lowercase hexadecimal characters.
func (c *Client) CreateUser(ctx context.Context) (string, error) {
	resp, err := c.svc.CreateUser(ctx, &identitypb.CreateUserRequest{})
	if err != nil {
		return "", mapErr(err)
	}
	return resp.OpaqueId, nil
}

// BulkCreateUsers creates count users in one streamed call and yields the
// opaque ID of each. The same idempotencyKey is always used with the same
// count: a repeated call under the key first yields the users the key
// already created that still exist, then creates the remainder, so an ID
// may be yielded by more than one call. When the relying party's user cap
// stops the creation, the iteration ends without an error after fewer than
// count IDs.
//
// Each range over the returned iterator issues a new call. Leaving the loop
// ends the call. An error ends the iteration after it is yielded.
func (c *Client) BulkCreateUsers(ctx context.Context, count uint32, idempotencyKey string) iter.Seq2[string, error] {
	return func(yield func(string, error) bool) {
		if err := checkUTF8("idempotencyKey", idempotencyKey); err != nil {
			yield("", err)
			return
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stream, err := c.svc.BulkCreateUsers(ctx, &identitypb.BulkCreateUsersRequest{
			Count:          count,
			IdempotencyKey: idempotencyKey,
		})
		if err != nil {
			yield("", mapErr(err))
			return
		}
		for {
			frame, err := stream.Recv()
			if err == io.EOF {
				return
			}
			if err != nil {
				yield("", mapErr(err))
				return
			}
			for _, id := range frame.GetChunk().GetOpaqueIds() {
				if !yield(id, nil) {
					return
				}
			}
		}
	}
}

// GetUser returns one user.
func (c *Client) GetUser(ctx context.Context, opaqueID string) (*User, error) {
	if err := checkUTF8("opaqueID", opaqueID); err != nil {
		return nil, err
	}
	resp, err := c.svc.GetUser(ctx, &identitypb.GetUserRequest{OpaqueId: opaqueID})
	if err != nil {
		return nil, mapErr(err)
	}
	return convertUser(resp)
}

// ExportUsers yields every user of the calling relying party, in no
// particular order. A non-empty startAfterID resumes the export after that
// opaque ID.
//
// Each range over the returned iterator issues a new call. Leaving the loop
// ends the call. An error ends the iteration after it is yielded.
func (c *Client) ExportUsers(ctx context.Context, startAfterID string) iter.Seq2[*User, error] {
	return func(yield func(*User, error) bool) {
		if err := checkUTF8("startAfterID", startAfterID); err != nil {
			yield(nil, err)
			return
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stream, err := c.svc.ExportUsers(ctx, &identitypb.ExportUsersRequest{StartAfterUserId: startAfterID})
		if err != nil {
			yield(nil, mapErr(err))
			return
		}
		for {
			page, err := stream.Recv()
			if err == io.EOF {
				return
			}
			if err != nil {
				yield(nil, mapErr(err))
				return
			}
			for _, u := range page.Users {
				user, err := convertUser(u)
				if err != nil {
					yield(nil, err)
					return
				}
				if !yield(user, nil) {
					return
				}
			}
		}
	}
}

// UpdateUserStatus locks or unlocks a user: status is UserStatusLocked or
// UserStatusActive.
func (c *Client) UpdateUserStatus(ctx context.Context, opaqueID string, status UserStatus) error {
	if err := checkUTF8("opaqueID", opaqueID); err != nil {
		return err
	}
	_, err := c.svc.UpdateUserStatus(ctx, &identitypb.UpdateUserStatusRequest{
		OpaqueId: opaqueID,
		Status:   identitypb.UserStatus(status),
	})
	if err != nil {
		return mapErr(err)
	}
	return nil
}

// DeleteUser deletes a user with its devices and challenges. The bans of
// its devices remain.
func (c *Client) DeleteUser(ctx context.Context, opaqueID string) error {
	if err := checkUTF8("opaqueID", opaqueID); err != nil {
		return err
	}
	if _, err := c.svc.DeleteUser(ctx, &identitypb.DeleteUserRequest{OpaqueId: opaqueID}); err != nil {
		return mapErr(err)
	}
	return nil
}

// UnlockUserRequestLimits restores all attempts of every per-user limit of
// a user. It is intended for the end of a recovery, after unanswered
// challenges of a lost phone have spent the user's attempts. Before a
// recovery it would also lift the protection the limits give against a
// flood of approval requests.
func (c *Client) UnlockUserRequestLimits(ctx context.Context, opaqueID string) error {
	if err := checkUTF8("opaqueID", opaqueID); err != nil {
		return err
	}
	if _, err := c.svc.UnlockUserRequestLimits(ctx, &identitypb.UnlockUserRequestLimitsRequest{OpaqueId: opaqueID}); err != nil {
		return mapErr(err)
	}
	return nil
}
