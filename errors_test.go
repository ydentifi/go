package ydentifi

import (
	"context"
	"errors"
	"strings"
	"testing"

	identitypb "github.com/ydentifi/go/internal/ydfi-proto-go/identity"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestStatusErrorMessage(t *testing.T) {
	se := &StatusError{Message: "user not found", TraceID: "4bf92f3577b34da6a3ce929d0e0e4736"}
	if got, want := se.Error(), "ydentifi: user not found (trace_id=4bf92f3577b34da6a3ce929d0e0e4736)"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	se.TraceID = ""
	if got, want := se.Error(), "ydentifi: user not found"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

// SDK-070: every code the server sends has its kind, the sentinel of the
// code; any other code has none.
func TestSDK070_EachCodeUnwrapsToItsKind(t *testing.T) {
	sentinels := map[codes.Code]error{
		codes.NotFound:           ErrNotFound,
		codes.AlreadyExists:      ErrAlreadyExists,
		codes.Unauthenticated:    ErrUnauthenticated,
		codes.PermissionDenied:   ErrPermissionDenied,
		codes.ResourceExhausted:  ErrResourceExhausted,
		codes.Unavailable:        ErrUnavailable,
		codes.InvalidArgument:    ErrInvalidArgument,
		codes.Internal:           ErrInternal,
		codes.FailedPrecondition: ErrFailedPrecondition,
		codes.Aborted:            ErrAborted,
		codes.DeadlineExceeded:   ErrDeadlineExceeded,
		codes.Canceled:           ErrCanceled,
	}
	for code := codes.OK; code <= codes.Unauthenticated; code++ {
		se := &StatusError{Code: code}
		want := sentinels[code]
		if got := se.Unwrap(); got != want {
			t.Errorf("%v: Unwrap() = %v, want %v", code, got, want)
		}
		if want != nil && !errors.Is(se, want) {
			t.Errorf("%v: errors.Is(err, %v) = false", code, want)
		}
	}
}

// SDK-070: a reason narrows the kind only under the code it belongs with,
// and the narrowed kind also matches its parent kind; the context errors
// match their codes.
func TestSDK070_AReasonNarrowsTheKindUnderItsCodeOnly(t *testing.T) {
	cases := []struct {
		code   codes.Code
		reason ErrorReason
		target error
		want   bool
	}{
		{codes.FailedPrecondition, ErrorReasonMaxDevicesReached, ErrDeviceLimitReached, true},
		{codes.InvalidArgument, ErrorReasonMaxDevicesReached, ErrDeviceLimitReached, false},
		{codes.FailedPrecondition, ErrorReasonUserLocked, ErrDeviceLimitReached, false},
		{codes.ResourceExhausted, ErrorReasonChallengeTooSoon, ErrChallengeTooSoon, true},
		{codes.FailedPrecondition, ErrorReasonChallengeTooSoon, ErrChallengeTooSoon, false},
		{codes.ResourceExhausted, ErrorReasonRateLimitExceeded, ErrChallengeTooSoon, false},
		{codes.FailedPrecondition, ErrorReasonTOTPLocked, ErrTOTPLocked, true},
		{codes.ResourceExhausted, ErrorReasonTOTPLocked, ErrTOTPLocked, false},
		{codes.FailedPrecondition, ErrorReasonUserLocked, ErrTOTPLocked, false},
		{codes.DeadlineExceeded, ErrorReasonUnspecified, context.DeadlineExceeded, true},
		{codes.Canceled, ErrorReasonUnspecified, context.DeadlineExceeded, false},
		{codes.Canceled, ErrorReasonUnspecified, context.Canceled, true},
		{codes.DeadlineExceeded, ErrorReasonUnspecified, context.Canceled, false},
		{codes.NotFound, ErrorReasonUserNotFound, ErrInvalidArgument, false},
	}
	for _, c := range cases {
		se := &StatusError{Code: c.code, Reason: c.reason}
		if got := errors.Is(se, c.target); got != c.want {
			t.Errorf("%v %v: errors.Is(err, %v) = %v, want %v", c.code, c.reason, c.target, got, c.want)
		}
	}
	// A reason sentinel also matches the sentinel of its code.
	for _, c := range []struct {
		code   codes.Code
		reason ErrorReason
		parent error
	}{
		{codes.ResourceExhausted, ErrorReasonChallengeTooSoon, ErrResourceExhausted},
		{codes.FailedPrecondition, ErrorReasonMaxDevicesReached, ErrFailedPrecondition},
		{codes.FailedPrecondition, ErrorReasonTOTPLocked, ErrFailedPrecondition},
	} {
		if se := (&StatusError{Code: c.code, Reason: c.reason}); !errors.Is(se, c.parent) {
			t.Errorf("%v %v does not match its parent kind %v", c.code, c.reason, c.parent)
		}
	}
}

// A string that is not valid UTF-8 is refused with an error that matches
// ErrInvalidArgument and is not a *StatusError.
func TestCheckUTF8(t *testing.T) {
	if err := checkUTF8("opaqueID", "abcé"); err != nil {
		t.Fatalf("valid UTF-8: %v", err)
	}
	err := checkUTF8("opaqueID", "abc\xff")
	var se *StatusError
	if !errors.Is(err, ErrInvalidArgument) || errors.As(err, &se) {
		t.Fatalf("invalid UTF-8: %v; want ErrInvalidArgument that is not a *StatusError", err)
	}
	if got, want := err.Error(), "ydentifi: opaqueID is not valid UTF-8: ydentifi: invalid argument"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestChallengeStatusIsTerminal(t *testing.T) {
	terminal := map[ChallengeStatus]bool{
		ChallengeStatusApproved: true, ChallengeStatusDenied: true, ChallengeStatusRejected: true,
		ChallengeStatusExpired: true, ChallengeStatusSuperseded: true, ChallengeStatusDismissed: true,
	}
	for s := ChallengeStatus(0); s <= 9; s++ {
		if got := s.IsTerminal(); got != terminal[s] {
			t.Errorf("%v.IsTerminal() = %v, want %v", s, got, terminal[s])
		}
	}
}

// SDK-074: an answer newer than the SDK keeps the kind of its code, its
// reason as a number and its fields; a code the SDK does not know matches no
// kind; the first ErrorDetail is read wherever it stands among the details.
func TestSDK074_AnAnswerNewerThanTheSDK(t *testing.T) {
	trace := strings.Repeat("ab", 16)
	detail := &identitypb.ErrorDetail{Reason: 9999, TraceId: trace, Field: "opaque_id", Subject: "s"}
	answer := func(code codes.Code, other bool) *StatusError {
		t.Helper()
		st := status.New(code, "refused")
		var err error
		if other {
			st, err = st.WithDetails(wrapperspb.String("newer"), detail)
		} else {
			st, err = st.WithDetails(detail)
		}
		if err != nil {
			t.Fatal(err)
		}
		var se *StatusError
		if !errors.As(mapErr(st.Err()), &se) {
			t.Fatalf("%v: not a *StatusError", code)
		}
		return se
	}
	for _, other := range []bool{false, true} {
		se := answer(codes.FailedPrecondition, other)
		if !errors.Is(se, ErrFailedPrecondition) || errors.Is(se, ErrDeviceLimitReached) || errors.Is(se, ErrTOTPLocked) {
			t.Errorf("other detail first %v: want ErrFailedPrecondition and no narrowed kind", other)
		}
		if se.Reason != 9999 || se.Reason.String() != "UNKNOWN_9999" || se.TraceID != trace || se.Field != "opaque_id" || se.Subject != "s" {
			t.Errorf("other detail first %v: reason %v (%d), trace %q, field %q, subject %q", other, se.Reason, int(se.Reason), se.TraceID, se.Field, se.Subject)
		}
	}
	se := answer(codes.Code(42), false)
	if se.Unwrap() != nil || se.Code != codes.Code(42) || se.Reason != 9999 || se.TraceID != trace {
		t.Errorf("code 42: Unwrap %v, code %v, reason %d, trace %q", se.Unwrap(), se.Code, int(se.Reason), se.TraceID)
	}
}

// SDK-075: each answer that carries a time, with one time field that is
// not RFC 3339, and then with every time the server may leave empty, empty.
func TestSDK075_AnAnswerTheSDKCannotRead(t *testing.T) {
	const good, bad = "2026-11-18T12:00:00Z", "yesterday"
	// Strings that are not RFC 3339 times: a word, and the forms a lenient
	// ISO 8601 reader takes.
	notTimes := []string{bad, "2026-11-18", "2026-11-18T12:00:00", "20261118T120000Z", "2026-11-18 12:00:00Z", "2026-11-18T12:00:00+0000"}
	pick := func(field, want, s string) string {
		if field == want {
			return s
		}
		return good
	}
	type answerCase struct {
		answer, field string
		convert       func(field, s string) (any, error)
	}
	var cases []answerCase
	for _, f := range []string{"created_at", "last_authenticated_at", "last_activity_at"} {
		cases = append(cases, answerCase{"user", f, func(field, s string) (any, error) {
			return convertUser(&identitypb.GetUserResponse{
				CreatedAt:           pick(field, "created_at", s),
				LastAuthenticatedAt: pick(field, "last_authenticated_at", s),
				LastActivityAt:      pick(field, "last_activity_at", s),
			})
		}})
	}
	for _, f := range []string{"created_at", "last_authenticated_at"} {
		cases = append(cases, answerCase{"device", f, func(field, s string) (any, error) {
			return convertDevice(&identitypb.DeviceSummary{
				CreatedAt:           pick(field, "created_at", s),
				LastAuthenticatedAt: pick(field, "last_authenticated_at", s),
			})
		}})
	}
	for _, f := range []string{"issued_at", "expires_at", "delivered_at"} {
		cases = append(cases, answerCase{"active challenge", f, func(field, s string) (any, error) {
			return convertActiveChallenge(&identitypb.ActiveChallengeSummary{
				IssuedAt:    pick(field, "issued_at", s),
				ExpiresAt:   pick(field, "expires_at", s),
				DeliveredAt: pick(field, "delivered_at", s),
			})
		}})
	}
	cases = append(cases, []answerCase{
		{"challenge", "expires_at", func(_, s string) (any, error) {
			return convertChallenge(&identitypb.IssueAuthChallengeResponse{ExpiresAt: s})
		}},
		{"wait-stream frame", "emitted_at", func(_, s string) (any, error) {
			return convertChallengeFrame(&identitypb.AwaitChallengeFrame{EmittedAt: s})
		}},
		{"enrollment invite", "expires_at", func(_, s string) (any, error) {
			return convertEnrollmentInvite(&identitypb.IssueEnrollmentInviteResponse{ExpiresAt: s})
		}},
		{"recovery invite", "expires_at", func(_, s string) (any, error) {
			return convertRecoveryInvite(&identitypb.IssueRecoveryInviteResponse{ExpiresAt: s})
		}},
	}...)

	for _, c := range cases {
		for _, s := range notTimes {
			_, err := c.convert(c.field, s)
			var se *StatusError
			switch {
			case !errors.Is(err, ErrMalformedResponse):
				t.Errorf("%s, %s %q: %v; want ErrMalformedResponse", c.answer, c.field, s, err)
			case errors.As(err, &se):
				t.Errorf("%s, %s: %v is a *StatusError", c.answer, c.field, err)
			case !strings.Contains(err.Error(), c.field):
				t.Errorf("%s: %q does not name %s", c.answer, err, c.field)
			}
		}
		if _, err := c.convert(c.field, good); err != nil {
			t.Errorf("%s, %s %q: %v", c.answer, c.field, good, err)
		}
	}

	// Two times that do not parse: the first is named.
	_, err := convertUser(&identitypb.GetUserResponse{CreatedAt: bad, LastActivityAt: bad})
	if err == nil || !strings.Contains(err.Error(), "created_at") || strings.Contains(err.Error(), "last_activity_at") {
		t.Errorf("two bad times: %v; want created_at named alone", err)
	}

	// The times the server may leave empty are the zero time.
	u, err := convertUser(&identitypb.GetUserResponse{CreatedAt: good})
	if err != nil || !u.LastAuthenticatedAt.IsZero() || !u.LastActivityAt.IsZero() {
		t.Errorf("user with empty times: %+v, %v", u, err)
	}
	d, err := convertDevice(&identitypb.DeviceSummary{CreatedAt: good})
	if err != nil || !d.LastAuthenticatedAt.IsZero() {
		t.Errorf("device with an empty time: %+v, %v", d, err)
	}
	f, err := convertChallengeFrame(&identitypb.AwaitChallengeFrame{})
	if err != nil || !f.EmittedAt.IsZero() {
		t.Errorf("frame with an empty time: %+v, %v", f, err)
	}
	a, err := convertActiveChallenge(&identitypb.ActiveChallengeSummary{IssuedAt: good, ExpiresAt: good})
	if err != nil || !a.DeliveredAt.IsZero() {
		t.Errorf("active challenge with an empty time: %+v, %v", a, err)
	}

	// A list ends at its first answer that cannot be read.
	devices, err := convertAll([]*identitypb.DeviceSummary{{CreatedAt: good}, {CreatedAt: bad}}, convertDevice)
	if !errors.Is(err, ErrMalformedResponse) || devices != nil {
		t.Errorf("list with a bad device: %v, %v; want ErrMalformedResponse and no list", devices, err)
	}
	devices, err = convertAll([]*identitypb.DeviceSummary{{CreatedAt: good}, {CreatedAt: good}}, convertDevice)
	if err != nil || len(devices) != 2 {
		t.Errorf("list of two devices: %v, %v", devices, err)
	}
}
