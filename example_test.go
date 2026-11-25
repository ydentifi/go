package ydentifi_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"
	"time"

	ydentifi "github.com/ydentifi/go"
)

// opaqueID stands for the opaque ID CreateUser returned for a user who has
// enrolled a phone.
const opaqueID = "8b2c4f1e9d7a6b5c3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d"

// ExampleNew builds a client from options. The other examples read
// YDFI_SERVER_ADDR, YDFI_TLS_CERT_PATH, YDFI_TLS_KEY_PATH and
// YDFI_TLS_CA_PATH from the environment.
func ExampleNew() {
	client, err := ydentifi.New(
		ydentifi.WithServerAddr("auth.acme.example:443"),
		ydentifi.WithCertFiles("/etc/acme/ydentifi.crt", "/etc/acme/ydentifi.key"),
		ydentifi.WithCAFile("/etc/acme/ydentifi-ca.crt"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// A deadline bounds the call when the network does not respond.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	id, err := client.CreateUser(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("created user:", id[:8]+"...")
}

func ExampleClient_CreateUser() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	id, err := client.CreateUser(ctx)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("created user:", id[:8]+"...")
}

func ExampleClient_GetUser() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	user, err := client.GetUser(ctx, opaqueID)
	if errors.Is(err, ydentifi.ErrNotFound) {
		fmt.Println("user not found")
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("status=%v last_activity=%s\n", user.Status, user.LastActivityAt.Format(time.DateOnly))
}

func ExampleClient_UpdateUserStatus() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.UpdateUserStatus(ctx, opaqueID, ydentifi.UserStatusLocked); err != nil {
		log.Fatal(err)
	}
	fmt.Println("user locked")
}

func ExampleClient_DeleteUser() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.DeleteUser(ctx, opaqueID); err != nil {
		log.Fatal(err)
	}
	fmt.Println("user deleted")
}

func ExampleClient_UnlockUserRequestLimits() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Called once a recovery has completed.
	if err := client.UnlockUserRequestLimits(ctx, opaqueID); err != nil {
		log.Fatal(err)
	}
	fmt.Println("request limits restored")
}

func ExampleClient_ExportUsers() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Each range issues one call; leaving the loop early ends it.
	for user, err := range client.ExportUsers(ctx, "") {
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("user=%s status=%v\n", user.OpaqueID[:8]+"...", user.Status)
	}
}

func ExampleClient_BulkCreateUsers() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// The idempotency key names one batch: the call repeated with the same
	// key resumes it without creating users twice, and a new batch takes a
	// new key. An ID may be yielded by more than one call, so the IDs are
	// kept as a set.
	const count = 10
	ids := map[string]bool{}
	for id, err := range client.BulkCreateUsers(ctx, count, "example-batch-1") {
		if err != nil {
			log.Fatal(err)
		}
		ids[id] = true
	}
	// Fewer IDs than requested means that the user cap stopped the creation.
	fmt.Printf("created=%d not_created=%d\n", len(ids), count-len(ids))
}

func ExampleClient_ListDevicesForUser() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	devices, err := client.ListDevicesForUser(ctx, opaqueID)
	if err != nil {
		log.Fatal(err)
	}
	for _, d := range devices {
		fmt.Printf("%s %v %v %s\n", d.DeviceID, d.Platform, d.Status, d.Model)
	}
}

func ExampleClient_RevokeDevice() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const deviceID = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
	if err := client.RevokeDevice(ctx, opaqueID, deviceID); err != nil {
		log.Fatal(err)
	}
	// The revoked device keeps the TOTP secret until it is replaced.
	if _, err := client.IssueUserTOTPEnrollment(ctx, opaqueID, false); err != nil {
		log.Fatal(err)
	}
	fmt.Println("device revoked and TOTP secret replaced")
}

func ExampleClient_BanDevice() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const deviceID = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
	n, err := client.BanDevice(ctx, opaqueID, deviceID, "reported stolen")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("devices banned:", n)
}

func ExampleClient_UnbanDevice() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The phone is named by one of the user's devices.
	err = client.UnbanDevice(ctx, ydentifi.UnbanDeviceRequest{
		OpaqueID: opaqueID,
		DeviceID: "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b",
	})
	if err != nil {
		log.Fatal(err)
	}

	// After DeleteUser no device remains, and the phone is named by its
	// permanent ID.
	err = client.UnbanDevice(ctx, ydentifi.UnbanDeviceRequest{
		OpaqueID:    opaqueID,
		PermanentID: "A1B2C3D4-E5F6-4711-8899-AABBCCDDEEFF",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("ban lifted")
}

func ExampleClient_IssueAuthChallenge() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ch, err := client.IssueAuthChallenge(ctx, ydentifi.IssueAuthChallengeRequest{
		OpaqueID: opaqueID,
		TTL:      time.Minute,
		Context:  []byte("Sign-in to the Acme Corp dashboard"),
		// The server refuses a challenge without a minimum strength.
		MinStrength: ydentifi.AuthStrengthDeviceAccess,
	})
	if err != nil {
		log.Fatal(err)
	}
	// QREncoded is rendered unchanged as a QR code.
	fmt.Println("challenge issued:", ch.ChallengeID)
}

func ExampleClient_AwaitChallenge() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The opaque ID CreateUser returned for a user who has enrolled a phone.
	const opaqueID = "8b2c4f1e9d7a6b5c3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d"

	ch, err := client.IssueAuthChallenge(ctx, ydentifi.IssueAuthChallengeRequest{
		OpaqueID:    opaqueID,
		Context:     []byte("Transfer of 1,000 EUR to ACME Corp"),
		MinStrength: ydentifi.AuthStrengthBiometric,
	})
	if err != nil {
		log.Fatal(err)
	}

	// The server ends the wait about 5 seconds after the challenge
	// expires; a deadline bounds it as well.
	wait, stop := context.WithTimeout(context.Background(), 90*time.Second)
	defer stop()

	for frame, err := range client.AwaitChallenge(wait, ch.ChallengeID) {
		if err != nil {
			log.Fatal(err)
		}
		if !frame.Status.IsTerminal() {
			continue // Pending or Delivered
		}
		switch frame.Status {
		case ydentifi.ChallengeStatusApproved:
			fmt.Println("approved")
		case ydentifi.ChallengeStatusDenied:
			// DeclineReasonNotMe reports an attempt the user did not make.
			fmt.Println("denied:", frame.DeclineReason)
		case ydentifi.ChallengeStatusRejected:
			// The user approved and a check refused the approval; this is
			// not a decline.
			fmt.Println("rejected:", frame.VerificationFailure)
		default:
			fmt.Println("ended:", frame.Status)
		}
	}
}

func ExampleClient_ListActiveChallenges() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	active, err := client.ListActiveChallenges(ctx, opaqueID)
	if err != nil {
		log.Fatal(err)
	}
	for _, c := range active {
		fmt.Printf("%s %v expires %s\n", c.ChallengeID, c.Status, c.ExpiresAt.Format(time.RFC3339))
	}
}

func ExampleClient_IssueUserTOTPEnrollment() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	enrolment, err := client.IssueUserTOTPEnrollment(ctx, opaqueID, true)
	if err != nil {
		log.Fatal(err)
	}
	// Formatting the enrolment redacts its secrets.
	fmt.Println(enrolment)
}

func ExampleClient_VerifyUserTOTP() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	valid, err := client.VerifyUserTOTP(ctx, opaqueID, "123456")
	if errors.Is(err, ydentifi.ErrTOTPLocked) {
		fmt.Println("TOTP codes are locked until the secret is replaced")
		return
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("valid:", valid)
}

func ExampleClient_IssueEnrollmentInvite() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	invite, err := client.IssueEnrollmentInvite(ctx, ydentifi.IssueEnrollmentInviteRequest{
		OpaqueID: opaqueID,
		TTL:      5 * time.Minute,
	})
	if err != nil {
		log.Fatal(err)
	}
	// QRPayload is rendered unchanged as a QR code.
	fmt.Println("invite expires at:", invite.ExpiresAt.Format(time.RFC3339))
}

// At the device limit, the authenticated user selects an active device to
// revoke before another invite is issued.
func ExampleClient_IssueEnrollmentInvite_deviceLimitReached() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// chosen is the device the authenticated user selected from the list.
	const chosen = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b"
	req := ydentifi.IssueEnrollmentInviteRequest{OpaqueID: opaqueID}

	invite, err := client.IssueEnrollmentInvite(ctx, req)
	if errors.Is(err, ydentifi.ErrDeviceLimitReached) {
		devices, err := client.ListDevicesForUser(ctx, opaqueID)
		if err != nil {
			log.Fatal(err)
		}
		var active []string
		for _, d := range devices {
			if d.Status == ydentifi.DeviceStatusActive {
				fmt.Printf("%s %s added %s, last used %s\n", d.DeviceID[:8], d.Model,
					d.CreatedAt.Format(time.DateOnly), d.LastAuthenticatedAt.Format(time.DateOnly))
				active = append(active, d.DeviceID)
			}
		}
		if !slices.Contains(active, chosen) {
			log.Fatal("the chosen device is not an active device of the user")
		}
		if err := client.RevokeDevice(ctx, opaqueID, chosen); err != nil {
			log.Fatal(err)
		}
		invite, err = client.IssueEnrollmentInvite(ctx, req)
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("invite expires at:", invite.ExpiresAt.Format(time.RFC3339))
}

func ExampleClient_IssueRecoveryInvite() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The user has been authenticated out of band before this call.
	invite, err := client.IssueRecoveryInvite(ctx, ydentifi.IssueRecoveryInviteRequest{OpaqueID: opaqueID})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("revoked %d devices; invite expires at %s\n", invite.RevokedDeviceCount, invite.ExpiresAt.Format(time.RFC3339))
}

func ExampleStatusError() {
	client, err := ydentifi.New()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = client.GetUser(ctx, opaqueID)
	var se *ydentifi.StatusError
	if errors.As(err, &se) {
		if se.Reason == ydentifi.ErrorReasonUserNotFound {
			fmt.Println("no such user:", se.Subject)
		}
		// The trace ID allows the deployment's operators to find the call.
		fmt.Printf("reason=%v trace=%s\n", se.Reason, se.TraceID)
	}
}

func ExampleChallengeStatus_IsTerminal() {
	fmt.Println("delivered:", ydentifi.ChallengeStatusDelivered.IsTerminal())
	fmt.Println("approved:", ydentifi.ChallengeStatusApproved.IsTerminal())
	fmt.Println("rejected:", ydentifi.ChallengeStatusRejected.IsTerminal())
	// Output:
	// delivered: false
	// approved: true
	// rejected: true
}
