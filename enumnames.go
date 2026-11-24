package ydentifi

import "strconv"

// enumName returns a protocol enum name, such as "APPROVED", or
// "UNKNOWN_<n>" for an unrecognised value.
func enumName(names []string, v int32) string {
	if v >= 0 && int(v) < len(names) && names[v] != "" {
		return names[v]
	}
	return "UNKNOWN_" + strconv.Itoa(int(v))
}

var (
	userStatusNames          = []string{"UNSPECIFIED", "ACTIVE", "LOCKED"}
	devicePlatformNames      = []string{"UNSPECIFIED", "IOS", "ANDROID"}
	deviceStatusNames        = []string{"UNSPECIFIED", "ACTIVE", "", "INACTIVE", "BANNED"}
	challengeStatusNames     = []string{"UNSPECIFIED", "PENDING", "DELIVERED", "APPROVED", "DENIED", "EXPIRED", "SUPERSEDED", "DISMISSED", "REJECTED"}
	challengeExpressionNames = []string{"UNSPECIFIED", "APPROVED", "DECLINED", "DISMISSED"}
	declineReasonNames       = []string{"UNSPECIFIED", "NOT_ME", "SECURITY_CONCERN", "WRONG_DETAILS", "CANCELLED"}
	verificationFailureNames = []string{"UNSPECIFIED", "LOCATION_MISMATCH", "WRONG_MATCH_CODE"}
	authStrengthNames        = []string{"UNSPECIFIED", "DEVICE_ACCESS", "BIOMETRIC"}
	locationBucketNames      = []string{"UNSPECIFIED", "WITHIN_RADIUS", "NEAR", "FAR", "UNAVAILABLE", "DENIED_BY_USER"}
	locationAccuracyNames    = []string{"UNSPECIFIED", "HIGH", "MEDIUM", "LOW"}
	locationEnforcementNames = []string{"UNSPECIFIED", "ADVISORY", "REQUIRED"}
)

// String returns the status's name, such as "ACTIVE".
func (s UserStatus) String() string { return enumName(userStatusNames, int32(s)) }

// String returns the platform's name, such as "IOS".
func (p DevicePlatform) String() string { return enumName(devicePlatformNames, int32(p)) }

// String returns the status's name, such as "BANNED".
func (s DeviceStatus) String() string { return enumName(deviceStatusNames, int32(s)) }

// String returns the status's name, such as "APPROVED".
func (s ChallengeStatus) String() string { return enumName(challengeStatusNames, int32(s)) }

// String returns the expression's name, such as "DECLINED".
func (e ChallengeExpression) String() string { return enumName(challengeExpressionNames, int32(e)) }

// String returns the reason's name, such as "NOT_ME".
func (r DeclineReason) String() string { return enumName(declineReasonNames, int32(r)) }

// String returns the failure's name, such as "LOCATION_MISMATCH".
func (f VerificationFailure) String() string { return enumName(verificationFailureNames, int32(f)) }

// String returns the strength's name, such as "BIOMETRIC".
func (s AuthStrength) String() string { return enumName(authStrengthNames, int32(s)) }

// String returns the bucket's name, such as "WITHIN_RADIUS".
func (b LocationBucket) String() string { return enumName(locationBucketNames, int32(b)) }

// String returns the accuracy's name, such as "HIGH".
func (a LocationAccuracy) String() string { return enumName(locationAccuracyNames, int32(a)) }

// String returns the enforcement's name, such as "REQUIRED".
func (e LocationEnforcement) String() string { return enumName(locationEnforcementNames, int32(e)) }
