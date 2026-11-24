package ydentifi

import (
	"context"

	identitypb "github.com/ydentifi/go/internal/ydfi-proto-go/identity"
)

// ListDevicesForUser returns a user's devices in every status: active,
// inactive and banned. Each carries the permanent ID of its phone, which is
// the same under every relying party and every deployment.
func (c *Client) ListDevicesForUser(ctx context.Context, opaqueID string) ([]*Device, error) {
	if err := checkUTF8("opaqueID", opaqueID); err != nil {
		return nil, err
	}
	resp, err := c.svc.ListDevicesForUser(ctx, &identitypb.ListDevicesForUserRequest{OpaqueId: opaqueID})
	if err != nil {
		return nil, mapErr(err)
	}
	return convertAll(resp.Devices, convertDevice)
}

// RevokeDevice moves a device from active to inactive and ends the user's
// open challenges. Revoking a device that is not active succeeds and
// changes nothing. The user's TOTP secret is not replaced.
func (c *Client) RevokeDevice(ctx context.Context, opaqueID, deviceID string) error {
	if err := checkUTF8("opaqueID", opaqueID); err != nil {
		return err
	}
	if err := checkUTF8("deviceID", deviceID); err != nil {
		return err
	}
	_, err := c.svc.RevokeDevice(ctx, &identitypb.RevokeDeviceRequest{OpaqueId: opaqueID, DeviceId: deviceID})
	if err != nil {
		return mapErr(err)
	}
	return nil
}

// BanDevice bans the phone of one of a user's devices from the calling
// relying party, by its permanent ID, and returns the number of active
// devices on that phone moved to banned: zero or one. The user's TOTP
// secret is not replaced.
func (c *Client) BanDevice(ctx context.Context, opaqueID, deviceID, reason string) (int32, error) {
	if err := checkUTF8("opaqueID", opaqueID); err != nil {
		return 0, err
	}
	if err := checkUTF8("deviceID", deviceID); err != nil {
		return 0, err
	}
	if err := checkUTF8("reason", reason); err != nil {
		return 0, err
	}
	resp, err := c.svc.BanDevice(ctx, &identitypb.BanDeviceRequest{OpaqueId: opaqueID, DeviceId: deviceID, Reason: reason})
	if err != nil {
		return 0, mapErr(err)
	}
	return resp.CascadedDeviceCount, nil
}

// UnbanDeviceRequest names the phone whose ban UnbanDevice lifts: by one of
// the user's devices, DeviceID, or by the phone's permanent ID,
// PermanentID. Exactly one of the two is set.
type UnbanDeviceRequest struct {
	// OpaqueID names the user. With PermanentID, the server checks only its
	// form, so an opaque ID of a deleted user is accepted.
	OpaqueID string
	// DeviceID names one of the user's devices, whose phone's ban is lifted.
	DeviceID string
	// PermanentID names the phone, as ListDevicesForUser returned it. After
	// DeleteUser, which deletes the devices and keeps their bans, it is the
	// only way to name the phone.
	PermanentID string
}

// UnbanDevice lifts a ban of the calling relying party on a phone. The
// banned devices of that phone move to inactive, not to active. Lifting a
// ban that does not exist succeeds and changes nothing. The request is sent
// as given: with both IDs set, or neither, the server refuses it.
func (c *Client) UnbanDevice(ctx context.Context, req UnbanDeviceRequest) error {
	if err := checkUTF8("OpaqueID", req.OpaqueID); err != nil {
		return err
	}
	if err := checkUTF8("DeviceID", req.DeviceID); err != nil {
		return err
	}
	if err := checkUTF8("PermanentID", req.PermanentID); err != nil {
		return err
	}
	_, err := c.svc.UnbanDevice(ctx, &identitypb.UnbanDeviceRequest{
		OpaqueId:    req.OpaqueID,
		DeviceId:    req.DeviceID,
		PermanentId: req.PermanentID,
	})
	if err != nil {
		return mapErr(err)
	}
	return nil
}
