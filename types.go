package ydentifi

import "time"

// UserStatus is the lifecycle state of a user identity.
type UserStatus int32

const (
	// UserStatusUnspecified is the zero value. UpdateUserStatus refuses it.
	UserStatusUnspecified UserStatus = 0
	// UserStatusActive is a user who may sign in.
	UserStatusActive UserStatus = 1
	// UserStatusLocked is a user the server refuses challenges, TOTP checks
	// and invites (reason USER_LOCKED).
	UserStatusLocked UserStatus = 2
)

// User is the SDK representation of an anonymous identity.
type User struct {
	// OpaqueID names the user: 64 lowercase hex characters.
	OpaqueID string
	// Status is whether the user is active or locked.
	Status UserStatus
	// CreatedAt is when the user was created.
	CreatedAt time.Time
	// LastAuthenticatedAt is the UTC day, at midnight, of the user's last
	// authentication: the day only, not the time. Zero until the first.
	LastAuthenticatedAt time.Time
	// LastActivityAt is the UTC day, at midnight, of the user's last
	// activity: the day only, not the time. Zero until the first.
	LastActivityAt time.Time
	// TOTPLocked indicates that TOTP verification is locked after 100
	// consecutive incorrect codes. IssueUserTOTPEnrollment with reuseExisting
	// false replaces the secret and unlocks verification. Status is unchanged.
	TOTPLocked bool
}

// DevicePlatform identifies the mobile operating system of an enrolled device.
type DevicePlatform int32

const (
	// DevicePlatformUnspecified is the zero value.
	DevicePlatformUnspecified DevicePlatform = 0
	// DevicePlatformIOS is an iPhone.
	DevicePlatformIOS DevicePlatform = 1
	// DevicePlatformAndroid is an Android phone.
	DevicePlatformAndroid DevicePlatform = 2
)

// DeviceStatus is the operational state of a registered authenticator.
type DeviceStatus int32

const (
	// DeviceStatusUnspecified is the zero value.
	DeviceStatusUnspecified DeviceStatus = 0
	// DeviceStatusActive is a device that can sign in and approve.
	DeviceStatusActive DeviceStatus = 1
	// DeviceStatusInactive indicates revocation or replacement. Re-enrolment
	// is required for subsequent use.
	DeviceStatusInactive DeviceStatus = 3
	// DeviceStatusBanned indicates that BanDevice banned the phone.
	DeviceStatusBanned DeviceStatus = 4
)

// Device is the RP-facing inventory view of an enrolled authenticator.
type Device struct {
	// DeviceID identifies one device enrolment by UUID and is accepted by
	// RevokeDevice, BanDevice and UnbanDevice.
	DeviceID string
	// PermanentID names the phone itself, and is the target of a ban. It is
	// the same under every relying party and every deployment, so relying
	// parties that compare their lists can link one handset's users.
	PermanentID string
	// Platform is the phone's operating system.
	Platform DevicePlatform
	// Status is whether the device is active, inactive or banned.
	Status DeviceStatus
	// CreatedAt is when the device was enrolled.
	CreatedAt time.Time
	// LastAuthenticatedAt is the UTC day, at midnight, of the device's last
	// authentication: the day only, not the time. Zero until the first.
	LastAuthenticatedAt time.Time
	// Name is the device's display name, or empty.
	Name string
	// Model is the device-declared hardware model at enrolment, such as
	// "iPhone17,4", or empty. The value is not independently verified.
	Model string
}

// EnrollmentInvite carries the artefacts the RP displays (as a QR code) for device enrolment.
// InviteToken and QRPayload are bearer secrets; printing the invite redacts them.
type EnrollmentInvite struct {
	// InviteToken is the invite's secret token.
	InviteToken []byte
	// QRPayload is what to show as a QR code for the Ydentifi app to scan.
	QRPayload []byte
	// ExpiresAt is when the invite can no longer be scanned.
	ExpiresAt time.Time
}

// RecoveryInvite contains an enrolment invite and the number of devices
// revoked by recovery. Formatting redacts InviteToken and QRPayload.
type RecoveryInvite struct {
	// InviteToken is the invite's secret token.
	InviteToken []byte
	// QRPayload is what to show as a QR code for the Ydentifi app to scan.
	QRPayload []byte
	// ExpiresAt is when the invite can no longer be scanned.
	ExpiresAt time.Time
	// RevokedDeviceCount is how many active devices the recovery revoked.
	RevokedDeviceCount uint32
}

// Challenge is the result of IssueAuthChallenge.
type Challenge struct {
	// ChallengeID identifies the challenge by a 26-character ULID and is
	// accepted by AwaitChallenge.
	ChallengeID string
	// QREncoded is the challenge URL. It must be rendered unchanged as a
	// QR code for the device to scan.
	QREncoded string
	// ExpiresAt is when the challenge expires unanswered.
	ExpiresAt time.Time
}

// ChallengeStatus is the lifecycle state of an auth challenge.
type ChallengeStatus int32

const (
	// ChallengeStatusUnspecified is the zero value.
	ChallengeStatusUnspecified ChallengeStatus = 0
	// ChallengeStatusPending is a challenge issued and not yet delivered to
	// a phone.
	ChallengeStatusPending ChallengeStatus = 1
	// ChallengeStatusDelivered is a challenge a phone has received and not
	// yet answered.
	ChallengeStatusDelivered ChallengeStatus = 2
	// ChallengeStatusApproved indicates that authentication passed all checks.
	// It is the only status that authorises access.
	ChallengeStatusApproved ChallengeStatus = 3
	// ChallengeStatusDenied indicates a user decline. DeclineReason records
	// the selected reason. This state is terminal.
	ChallengeStatusDenied ChallengeStatus = 4
	// ChallengeStatusExpired indicates that the response deadline elapsed
	// without an answer. This state is terminal.
	ChallengeStatusExpired ChallengeStatus = 5
	// ChallengeStatusSuperseded indicates that a wait was replaced, for example
	// by another wait on the same challenge. It terminates the current stream.
	ChallengeStatusSuperseded ChallengeStatus = 6
	// ChallengeStatusDismissed indicates that the user dismissed the challenge
	// without approving or declining it. It is terminal.
	ChallengeStatusDismissed ChallengeStatus = 7

	// ChallengeStatusRejected indicates that user approval failed verification,
	// such as a required location or match code check. Expression is
	// ChallengeExpressionApproved; the result must not be recorded as a
	// user decline.
	ChallengeStatusRejected ChallengeStatus = 8
)

// ChallengeExpression records the user's response separately from the
// verification outcome. User approval that fails verification has status
// Rejected and expression Approved.
type ChallengeExpression int32

const (
	// ChallengeExpressionUnspecified indicates no user response, including
	// pending and expired challenges.
	ChallengeExpressionUnspecified ChallengeExpression = 0
	// ChallengeExpressionApproved indicates user approval.
	ChallengeExpressionApproved ChallengeExpression = 1
	// ChallengeExpressionDeclined indicates a user decline.
	ChallengeExpressionDeclined ChallengeExpression = 2
	// ChallengeExpressionDismissed indicates dismissal without approval
	// or decline.
	ChallengeExpressionDismissed ChallengeExpression = 3
)

// DeclineReason records the reason selected by the user on a Denied result.
// Verification failures are reported separately by VerificationFailure on
// a Rejected result.
type DeclineReason int32

const (
	// DeclineReasonUnspecified is the zero value: no reason given.
	DeclineReasonUnspecified DeclineReason = 0
	// DeclineReasonNotMe indicates that the user did not initiate the request
	// and may indicate fraud.
	DeclineReasonNotMe DeclineReason = 1
	// DeclineReasonSecurityConcern indicates suspicion without a specific claim.
	DeclineReasonSecurityConcern DeclineReason = 2
	// DeclineReasonWrongDetails indicates unexpected request details, such as
	// an incorrect amount or payee.
	DeclineReasonWrongDetails DeclineReason = 3
	// DeclineReasonCancelled indicates cancellation or accidental interaction
	// and does not itself indicate fraud.
	DeclineReasonCancelled DeclineReason = 4
)

// VerificationFailure is the check that refused an authentication the
// user had agreed to. It is set only on a Rejected result.
type VerificationFailure int32

const (
	// VerificationFailureUnspecified indicates no failed verification check
	// and is used for results other than Rejected.
	VerificationFailureUnspecified VerificationFailure = 0

	// VerificationFailureLocationMismatch indicates that a required location
	// was not satisfied, including when the device reports no location.
	VerificationFailureLocationMismatch VerificationFailure = 1

	// VerificationFailureWrongMatchCode indicates that the submitted number
	// differs from the issued number. This may indicate approval of a request
	// originating from another session.
	VerificationFailureWrongMatchCode VerificationFailure = 2
)

// AuthStrength is a class of device-side authentication check. It appears in
// two places: on IssueAuthChallengeRequest as the minimum a response must
// satisfy, and on ChallengeResult as the tier the device reported achieving.
// The server rejects issuance when the minimum is left AuthStrengthUnspecified.
type AuthStrength int32

const (
	// AuthStrengthUnspecified is the wire-zero default; issuance is rejected
	// until it is set explicitly.
	AuthStrengthUnspecified AuthStrength = 0
	// AuthStrengthDeviceAccess indicates device unlock by biometrics or passcode.
	AuthStrengthDeviceAccess AuthStrength = 1
	// AuthStrengthBiometric indicates biometric authentication without passcode
	// fallback. It is the highest supported strength.
	AuthStrengthBiometric AuthStrength = 2
	// Value 3 is reserved and must not be reused.
)

// LocationBucket is the coarse location result the device reports back. A
// LocationResult carries no coordinates.
type LocationBucket int32

const (
	// LocationBucketUnspecified is the zero value.
	LocationBucketUnspecified LocationBucket = 0
	// LocationBucketWithinRadius indicates a location inside the radius.
	LocationBucketWithinRadius LocationBucket = 1
	// LocationBucketNear indicates a location outside but near the radius.
	LocationBucketNear LocationBucket = 2
	// LocationBucketFar indicates a location far outside the radius.
	LocationBucketFar LocationBucket = 3
	// LocationBucketUnavailable indicates that a location could not be obtained.
	LocationBucketUnavailable LocationBucket = 4
	// LocationBucketDeniedByUser indicates that location access was refused
	// by the user.
	LocationBucketDeniedByUser LocationBucket = 5
)

// LocationAccuracy is the bucketed confidence in the location measurement.
type LocationAccuracy int32

const (
	// LocationAccuracyUnspecified is the zero value.
	LocationAccuracyUnspecified LocationAccuracy = 0
	// LocationAccuracyHigh is a precise fix.
	LocationAccuracyHigh LocationAccuracy = 1
	// LocationAccuracyMedium is a fix of moderate precision.
	LocationAccuracyMedium LocationAccuracy = 2
	// LocationAccuracyLow is a coarse fix.
	LocationAccuracyLow LocationAccuracy = 3
)

// LocationEnforcement controls how a LocationConstraint is interpreted by the device.
type LocationEnforcement int32

const (
	// LocationEnforcementUnspecified is the zero value and is rejected.
	// Advisory or Required must be selected explicitly.
	LocationEnforcementUnspecified LocationEnforcement = 0
	// LocationEnforcementAdvisory reports where the device was without
	// refusing an approval for it.
	LocationEnforcementAdvisory LocationEnforcement = 1
	// LocationEnforcementRequired turns an approval from outside the radius
	// into ChallengeStatusRejected with VerificationFailureLocationMismatch.
	LocationEnforcementRequired LocationEnforcement = 2
)

// LocationConstraint is an optional geofence the device evaluates client-side.
type LocationConstraint struct {
	// Latitude is the centre latitude in degrees, from -90 to 90.
	Latitude float64
	// Longitude is the centre longitude in degrees, from -180 to 180.
	Longitude float64
	// RadiusMeters is the radius in metres, from 50 to 500,000.
	RadiusMeters uint32
	// Enforcement determines whether a location outside the radius rejects
	// approval. LocationEnforcementUnspecified is rejected.
	Enforcement LocationEnforcement
}

// LocationResult is the device-evaluated outcome of a LocationConstraint.
type LocationResult struct {
	// Bucket is where the device was, relative to the radius.
	Bucket LocationBucket
	// Accuracy is how precise the device's fix was.
	Accuracy LocationAccuracy
}

// ChallengeResult is one frame of an AwaitChallenge stream, a non-terminal
// state or the outcome. Only ChallengeStatusApproved authorises access.
// Expression records the user's response independently of verification.
type ChallengeResult struct {
	// Status is the challenge state.
	Status ChallengeStatus
	// Expression is the user's response.
	Expression ChallengeExpression
	// Signature is the device's signature, set on Approved, Denied and
	// Rejected. It is retained as an opaque record; the device's public key
	// is not available through this API for independent verification.
	Signature []byte

	// DeclineReason is set only when Status is ChallengeStatusDenied.
	DeclineReason DeclineReason

	// VerificationFailure is set only when Status is
	// ChallengeStatusRejected.
	VerificationFailure VerificationFailure

	// LocationResult is set only when the phone reported a location; it is
	// nil otherwise.
	LocationResult *LocationResult
	// EmittedAt is when the server sent this frame.
	EmittedAt time.Time

	// AuthStrength is the device-reported strength, bound into its signed
	// response. It is set for device responses, including declines, and is
	// AuthStrengthUnspecified for expiry or supersession.
	//
	// Only an Approved result confirms that the reported strength satisfies
	// the requested MinStrength. Declines are accepted without satisfying
	// that minimum. The reported strength cannot be independently verified
	// through this API.
	AuthStrength AuthStrength
}

// ActiveChallenge is a summary of an in-flight challenge.
type ActiveChallenge struct {
	// ChallengeID names the challenge.
	ChallengeID string
	// Status is ChallengeStatusPending or ChallengeStatusDelivered.
	Status ChallengeStatus
	// Context is the text the challenge asks the user to approve.
	Context []byte
	// LocationConstraint is the challenge's geofence, or nil.
	LocationConstraint *LocationConstraint
	// IssuedAt is when the challenge was issued.
	IssuedAt time.Time
	// ExpiresAt is when the challenge expires unanswered.
	ExpiresAt time.Time
	// DeliveredAt is the device delivery time, or the zero time while pending.
	DeliveredAt time.Time
}

// TOTPEnrollment carries the materials for TOTP setup. All three fields carry
// the TOTP secret; printing the enrolment redacts them.
type TOTPEnrollment struct {
	// QRCodePNGBase64 is TOTPURL as a 255x255 QR code: a PNG, base64
	// encoded.
	QRCodePNGBase64 string
	// TOTPURL is the otpauth://totp/ URL. Its label may be changed, for
	// example to display the user's name in an authenticator app.
	TOTPURL string
	// SecretBase32 is the secret in base32, for users who type it in.
	SecretBase32 string
}
