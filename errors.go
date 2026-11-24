package ydentifi

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf8"

	identitypb "github.com/ydentifi/go/internal/ydfi-proto-go/identity"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Sentinel errors. A *StatusError matches the sentinel of its gRPC code
// through errors.Is, and the three reason sentinels match under their code
// only.
var (
	// ErrNotFound reports that the user, device or challenge does not exist
	// for the calling relying party. Another relying party's receives the
	// same answer.
	ErrNotFound = errors.New("ydentifi: not found")

	// ErrAlreadyExists reports that what the call would create already
	// exists, as on a repeated request with the same ChallengeID.
	ErrAlreadyExists = errors.New("ydentifi: already exists")

	// ErrUnauthenticated reports that the server refused the client
	// certificate after the TLS handshake: it names no relying party the
	// server knows, or it expired after the connection opened.
	ErrUnauthenticated = errors.New("ydentifi: unauthenticated")

	// ErrPermissionDenied reports that the relying party is disabled.
	ErrPermissionDenied = errors.New("ydentifi: permission denied")

	// ErrResourceExhausted reports a spent per-user limit
	// (RATE_LIMIT_EXCEEDED), the relying party's user cap
	// (MAX_USERS_REACHED) or a challenge issued too soon after the last
	// (CHALLENGE_TOO_SOON).
	ErrResourceExhausted = errors.New("ydentifi: resource exhausted")

	// ErrUnavailable reports that the server could not be reached, that the
	// TLS handshake failed, or that the deployment exceeds its licence
	// (LICENSE_USER_CAP_REACHED).
	ErrUnavailable = errors.New("ydentifi: server unavailable")

	// ErrInvalidArgument reports a request that the server refused as
	// invalid, with StatusError.Field naming the field. It also matches the
	// error a method returns, before any request is sent, for a string
	// argument that is not valid UTF-8 or for a TTL below zero or of 2^32
	// seconds or more; that error is not a *StatusError.
	ErrInvalidArgument = errors.New("ydentifi: invalid argument")

	// ErrInternal reports a failure of the server. StatusError.TraceID
	// allows the deployment's operators to find the call in the server's
	// logs.
	ErrInternal = errors.New("ydentifi: server internal error")

	// ErrAborted reports a concurrent call on the same user, device or key
	// that held a lock too long. The call changed nothing and may be
	// repeated.
	ErrAborted = errors.New("ydentifi: aborted")

	// ErrDeadlineExceeded reports a call that ran past its deadline. A
	// *StatusError with this code also matches context.DeadlineExceeded.
	ErrDeadlineExceeded = errors.New("ydentifi: deadline exceeded")

	// ErrCanceled reports a cancelled call, including a call ended or made
	// after Close. A *StatusError with this code also matches
	// context.Canceled.
	ErrCanceled = errors.New("ydentifi: canceled")

	// ErrFailedPrecondition reports a user or deployment state that does
	// not allow the call. StatusError.Reason names the state.
	ErrFailedPrecondition = errors.New("ydentifi: failed precondition")

	// ErrDeviceLimitReached reports that IssueEnrollmentInvite was refused
	// because the user has three active devices. It matches only the reason
	// MAX_DEVICES_REACHED under the code FailedPrecondition.
	ErrDeviceLimitReached = errors.New("ydentifi: device limit reached")

	// ErrChallengeTooSoon reports that the user's newest challenge is still
	// open and less than 15 seconds old. The refusal spends none of the
	// user's attempts; StatusError.AutoExpiresAt is the time from which a
	// new challenge is admitted. It matches only the reason
	// CHALLENGE_TOO_SOON under the code ResourceExhausted.
	ErrChallengeTooSoon = errors.New("ydentifi: challenge too soon")

	// ErrTOTPLocked reports that 100 consecutive incorrect codes have locked
	// the user's TOTP verification. IssueUserTOTPEnrollment with
	// reuseExisting false replaces the secret and lifts the lock. It
	// matches only the reason TOTP_LOCKED under the code
	// FailedPrecondition.
	ErrTOTPLocked = errors.New("ydentifi: totp locked")

	// ErrConfiguration reports a missing, invalid or conflicting client
	// configuration. A file is named by its base name only. It is not a
	// *StatusError.
	ErrConfiguration = errors.New("ydentifi: configuration")

	// ErrMalformedResponse reports an answer of the server that the client
	// cannot read, such as a time that is not RFC 3339. It is not a
	// *StatusError.
	ErrMalformedResponse = errors.New("ydentifi: malformed response")
)

// configErr returns an error that wraps ErrConfiguration.
func configErr(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrConfiguration}, args...)...)
}

// checkUTF8 returns an error that wraps ErrInvalidArgument when s is not
// valid UTF-8, which no protobuf string field may carry.
func checkUTF8(name, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("ydentifi: %s is not valid UTF-8: %w", name, ErrInvalidArgument)
	}
	return nil
}

// ttlSeconds returns a TTL in whole seconds, as the uint32 field
// ttl_seconds carries it. A TTL below zero, or of 2^32 seconds or more,
// which the field cannot carry, returns an error that wraps
// ErrInvalidArgument.
func ttlSeconds(ttl time.Duration) (uint32, error) {
	if ttl < 0 || ttl/time.Second > math.MaxUint32 {
		return 0, fmt.Errorf("ydentifi: TTL %v is not from 0 to %d seconds: %w", ttl, uint32(math.MaxUint32), ErrInvalidArgument)
	}
	return uint32(ttl / time.Second), nil
}

// StatusError is an error status returned by the server or by gRPC: its
// code, and the reason, trace ID, field, subject and retry time of the
// server's ErrorDetail when the status carries one.
type StatusError struct {
	// Code is the gRPC status code.
	Code codes.Code

	// Reason is the server's reason, or ErrorReasonUnspecified when the
	// status carries no ErrorDetail.
	Reason ErrorReason

	// Message is the status message.
	Message string

	// TraceID is the call's W3C trace ID, 32 hexadecimal characters, or
	// empty. It allows the deployment's operators to find the call in the
	// server's logs.
	TraceID string

	// Field is the request field that failed validation, or empty.
	Field string

	// Subject is what the refusal refers to, or empty: the opaque ID on
	// USER_NOT_FOUND, the device ID on DEVICE_NOT_FOUND, and the limit on
	// RATE_LIMIT_EXCEEDED and CHALLENGE_TOO_SOON.
	Subject string

	// AutoExpiresAt is the time from which the refused call is admitted
	// again, set on RATE_LIMIT_EXCEEDED from a per-user limit and on
	// CHALLENGE_TOO_SOON. It is the zero time when the server sent none.
	AutoExpiresAt time.Time

	status *status.Status
}

// Error returns the status message, with the trace ID when there is one.
func (e *StatusError) Error() string {
	if e.TraceID != "" {
		return fmt.Sprintf("ydentifi: %s (trace_id=%s)", e.Message, e.TraceID)
	}
	return "ydentifi: " + e.Message
}

// GRPCStatus returns the gRPC status the error was made from, with every
// detail the server attached, so that status.Code and status.FromError
// read the error as that status.
func (e *StatusError) GRPCStatus() *status.Status {
	return e.status
}

// Unwrap returns the sentinel of the error's code, or nil for a code that
// has none.
func (e *StatusError) Unwrap() error {
	return sentinelForCode(e.Code)
}

// Is reports whether the error matches a reason sentinel or a context
// error: ErrDeviceLimitReached and ErrTOTPLocked under FailedPrecondition,
// ErrChallengeTooSoon under ResourceExhausted, context.DeadlineExceeded
// under DeadlineExceeded and context.Canceled under Canceled. The code
// sentinels match through Unwrap.
func (e *StatusError) Is(target error) bool {
	switch target {
	case context.DeadlineExceeded:
		return e.Code == codes.DeadlineExceeded
	case context.Canceled:
		return e.Code == codes.Canceled
	case ErrDeviceLimitReached:
		return e.Code == codes.FailedPrecondition && e.Reason == ErrorReasonMaxDevicesReached
	case ErrChallengeTooSoon:
		return e.Code == codes.ResourceExhausted && e.Reason == ErrorReasonChallengeTooSoon
	case ErrTOTPLocked:
		return e.Code == codes.FailedPrecondition && e.Reason == ErrorReasonTOTPLocked
	}
	return false
}

// mapErr converts an error of a gRPC call into a *StatusError, with the
// fields of the first ErrorDetail the status carries.
func mapErr(err error) error {
	st := status.Convert(err)
	se := &StatusError{Code: st.Code(), Message: st.Message(), status: st}
	for _, d := range st.Details() {
		if det, ok := d.(*identitypb.ErrorDetail); ok {
			se.Reason = ErrorReason(det.Reason)
			se.TraceID = det.TraceId
			se.Field = det.Field
			se.Subject = det.Subject
			if det.AutoExpiresAtUnixMs > 0 {
				se.AutoExpiresAt = time.UnixMilli(det.AutoExpiresAtUnixMs).UTC()
			}
			break
		}
	}
	return se
}

// sentinelForCode returns the sentinel of a gRPC code, or nil for a code
// that the server does not send.
func sentinelForCode(c codes.Code) error {
	switch c {
	case codes.NotFound:
		return ErrNotFound
	case codes.AlreadyExists:
		return ErrAlreadyExists
	case codes.Unauthenticated:
		return ErrUnauthenticated
	case codes.PermissionDenied:
		return ErrPermissionDenied
	case codes.ResourceExhausted:
		return ErrResourceExhausted
	case codes.Unavailable:
		return ErrUnavailable
	case codes.InvalidArgument:
		return ErrInvalidArgument
	case codes.Internal:
		return ErrInternal
	case codes.FailedPrecondition:
		return ErrFailedPrecondition
	case codes.Aborted:
		return ErrAborted
	case codes.DeadlineExceeded:
		return ErrDeadlineExceeded
	case codes.Canceled:
		return ErrCanceled
	}
	return nil
}
