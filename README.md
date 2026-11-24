<p align="center">
  <img src="./.assets/ydentifi-logo.png" alt="Ydentifi" width="120">
</p>

<h1 align="center">Ydentifi Go Client</h1>

<p align="center">
  <a href="https://pkg.go.dev/github.com/ydentifi/go"><img src="https://img.shields.io/badge/godoc-reference-1BA1C0?style=flat-square" alt="Go Reference"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/go-1.26%2B-1BA1C0?style=flat-square" alt="Go Version"></a>
  <a href="https://github.com/ydentifi/go/releases"><img src="https://img.shields.io/badge/release-v0.1.3-1BA1C0?style=flat-square" alt="Release"></a>
  <a href="https://ydentifi.io"><img src="https://img.shields.io/badge/ydentifi-identity%20server-1BA1C0?style=flat-square" alt="Ydentifi"></a>
</p>

The Go client for the Ydentifi identity server. A relying party uses it to create anonymous users, to enroll their phones, and to ask them to approve sign-ins and actions. It speaks gRPC over mutual TLS.

```bash
go get github.com/ydentifi/go
```

Go 1.26.11 or later is required. The module path ends in `/go`; the package name is `ydentifi`.

---

## Contents

- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Error handling](#error-handling)
- [Limits](#limits)
- [Deadlines](#deadlines)
- [Streaming](#streaming)
- [Concurrency](#concurrency)
- [API reference](#api-reference)
  - [Users](#users)
    - [CreateUser](#createuser) · [BulkCreateUsers](#bulkcreateusers) · [GetUser](#getuser) · [ExportUsers](#exportusers) · [UpdateUserStatus](#updateuserstatus) · [DeleteUser](#deleteuser) · [UnlockUserRequestLimits](#unlockuserrequestlimits)
  - [Devices](#devices)
    - [ListDevicesForUser](#listdevicesforuser) · [RevokeDevice](#revokedevice) · [BanDevice](#bandevice) · [UnbanDevice](#unbandevice)
  - [Challenges](#challenges)
    - [IssueAuthChallenge](#issueauthchallenge) · [AwaitChallenge](#awaitchallenge) · [ListActiveChallenges](#listactivechallenges)
  - [TOTP](#totp)
    - [IssueUserTOTPEnrollment](#issueusertotpenrollment) · [VerifyUserTOTP](#verifyusertotp)
  - [Enrollment and recovery](#enrollment-and-recovery)
    - [IssueEnrollmentInvite](#issueenrollmentinvite) · [IssueRecoveryInvite](#issuerecoveryinvite)
- [Types](#types)
- [Version](#version)
- [Examples](#examples)

---

## Quick start

```go
package main

import (
	"context"
	"log"
	"time"

	ydentifi "github.com/ydentifi/go"
)

func main() {
	client, err := ydentifi.New(
		ydentifi.WithServerAddr("auth.example.com:443"),
		ydentifi.WithCertFiles("/etc/ydentifi/rp.crt", "/etc/ydentifi/rp.key"),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	opaqueID, err := client.CreateUser(ctx)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("created user:", opaqueID)
}
```

One `Client` is built with `New`, shared by all goroutines, and closed with `Close` when it is no longer needed. `New` does not connect; the first call does.

---

## Configuration

`New` applies its options in order; a later option replaces what an earlier one set. Whatever the options leave unset is read from the environment.

**Required**

| Variable | Option | Purpose |
|---|---|---|
| `YDFI_SERVER_ADDR` | `WithServerAddr(host:port)` | The identity server's address |
| `YDFI_TLS_CERT_PATH` | `WithCertFiles` or `WithCert` | The relying party's client certificate (PEM) |
| `YDFI_TLS_KEY_PATH` | `WithCertFiles` or `WithCert` | Its private key (PEM) |
| `YDFI_TLS_CA_PATH` | `WithCAFile` or `WithCA` | The deployment's CA bundle that verifies the server (PEM) |

The two certificate variables are used only together.

**Optional**

| Variable | Option | Purpose |
|---|---|---|
| `YDFI_SERVER_NAME` | `WithServerName` | The name the server's certificate is verified against. Required when the address is an IP address |
| — | `WithUserAgent(ua)` | Replaces the default user agent, `ydentifi-go/<version>` |
| — | `WithKeepalive(params)` | gRPC keepalive pings from the client |
| — | `WithLogger(logger)` | Where the client reports certificate files it does not use (described below). The default, and the logger `nil` selects, is `slog.Default()` |
| — | `WithDialOptions(...)` | Further `grpc.DialOption`s. The client's TLS credentials, user agent and keepalive parameters are applied after them and take precedence. A service config from name resolution (a DNS TXT record) is ignored; one is given with `grpc.WithDefaultServiceConfig` |

The two combinations `New` refuses are a certificate given both by `WithCertFiles` and by `WithCert`, and a CA bundle given both by `WithCAFile` and by `WithCA`.

### The address

The address is a host with an optional port, checked by these rules:

1. An empty address is refused, as is one that holds any of `/ ? # @` or white space. A URL scheme such as `grpc://` is therefore refused.
2. The address has one of three shapes: `[v6]:port`, where `v6` is an IPv6 address (a zone is allowed); `host:port`, with exactly one colon; or a host with no colon. Anything else is refused: more than one colon outside brackets, a stray `[` or `]`, brackets that do not hold an IPv6 address, or an empty host.
3. A port is ASCII decimal digits with a value from 1 to 65535; leading zeros are allowed, and an empty port is refused.
4. A host that is an IP address requires `WithServerName` or `YDFI_SERVER_NAME`, which is then the verification name. For any other host, the verification name is the server name when one is given, or else the host in lower case.

Host shapes such as `127.1`, `0x7f.1` or `2130706433` are names under these rules, not IP addresses: the server's certificate does not carry them, so TLS verification refuses them at the first call, with `ErrUnavailable`. The address is always resolved through DNS: `unix:443` names the host `unix`, never a local socket.

`New` returns an error that matches `ErrConfiguration` when:

- the address, the certificate and key, or the CA bundle are missing;
- the address breaks the rules above;
- the certificate, or the CA bundle, is given both as files and as PEM;
- a file cannot be read (the error names it by its base name only, never its directory);
- the certificate, key or CA bundle does not parse, including any one certificate of a chain or bundle, or the key is not the certificate's;
- a CA bundle is given but holds no certificate;
- gRPC cannot build a connection from the dial options.

### The three certificate inputs

Mutual TLS authenticates both ends of the connection. Three inputs are involved:

- **The client certificate** (`YDFI_TLS_CERT_PATH`, `WithCertFiles`, `WithCert`) identifies the relying party to the server. It names the relying party's ID, and the deployment's certificate authority issued it. The server accepts any certificate that authority issued for that ID until it expires, so a renewed certificate works beside the old one, and a leaked key works until its certificate expires.
- **The private key** (`YDFI_TLS_KEY_PATH`, `WithCertFiles`, `WithCert`) proves possession of that certificate. Its file is to be readable by the relying party's process only.
- **The CA bundle** (`YDFI_TLS_CA_PATH`, `WithCAFile`, `WithCA`) works the other way: it allows the client to check that it reached the real server. It is required, and the deployment's operator provides it: the server's certificate comes from the deployment's own CA, and the system trust store, which would trust any server a public CA names for the host, is never used. The server's certificate is also required to name it a Ydentifi server, with one URI of the form `spiffe://<trust domain>/server/<name>`; any other server is refused at the TLS handshake, with `ErrUnavailable`.

### Renewing the certificate

A certificate given by files (`WithCertFiles`, or `YDFI_TLS_CERT_PATH` and `YDFI_TLS_KEY_PATH`) is read by `New`, and read again at each new connection, during its TLS handshake. A pair that parses and is within its validity period is presented; a renewed certificate written to the same files is therefore used from the next connection onwards.

The server closes every connection at its maximum connection age: 30 minutes by default, and 24 hours at most. A renewed certificate is therefore in use within that age, and a certificate is to be renewed at least that long before it expires. Calls in flight are not affected by a renewal.

Each file is to be replaced atomically: a new file is written and then renamed over the old one. A pair that cannot be read, does not parse, or is outside its validity period is not presented; the certificate in use is presented again, and the refusal is logged at `Warn`, once while the same problem lasts, with the files named by their base names only.

A certificate given with `WithCert` is used for the client's lifetime; a new client is built to renew it. `WithCert` does not copy its arguments, which are not to be modified after the call.

### Strings

A string argument that is not valid UTF-8 is refused before any request is sent, with an error that matches `ErrInvalidArgument` and is not a `*StatusError`: no protobuf string field can carry it. Byte arguments such as `Context` are sent as they are, and the server judges them.

---

## Error handling

Every error a call returns can be examined in two ways.

**By kind**, with `errors.Is` and a sentinel:

```go
_, err := client.GetUser(ctx, opaqueID)
if errors.Is(err, ydentifi.ErrNotFound) {
	// no such user
}
```

**By detail**, with `errors.As` and `*StatusError`:

```go
var se *ydentifi.StatusError
if errors.As(err, &se) {
	log.Printf("code=%v reason=%v trace=%s subject=%s", se.Code, se.Reason, se.TraceID, se.Subject)
	if se.Reason == ydentifi.ErrorReasonUserLocked {
		// the user is locked
	}
}
```

Both apply to the same error.

### Error kinds

| Sentinel | gRPC code | Meaning |
|---|---|---|
| `ErrNotFound` | `NotFound` | The user, device or challenge does not exist for the calling relying party. Another relying party's receives the same answer |
| `ErrAlreadyExists` | `AlreadyExists` | What the call would create already exists, as on a repeated request with the same `ChallengeID` |
| `ErrUnauthenticated` | `Unauthenticated` | The certificate passed the TLS handshake, but the server refused it: it names no relying party the server knows, or it expired after the connection opened |
| `ErrPermissionDenied` | `PermissionDenied` | The deployment's operator has disabled the relying party |
| `ErrResourceExhausted` | `ResourceExhausted` | A per-user limit is spent (reason `RATE_LIMIT_EXCEEDED`), the relying party's user cap is reached (`MAX_USERS_REACHED`), or the relying party holds 1,000 bulk-create keys |
| `ErrChallengeTooSoon` | `ResourceExhausted` | The user's newest challenge is still open and less than 15 seconds old. It also matches `ErrResourceExhausted` |
| `ErrFailedPrecondition` | `FailedPrecondition` | The call is valid, but the user or the deployment is not in a state that allows it. `Reason` names the state |
| `ErrDeviceLimitReached` | `FailedPrecondition` | The user already has 3 active devices. It also matches `ErrFailedPrecondition` |
| `ErrTOTPLocked` | `FailedPrecondition` | The user's TOTP codes are locked after 100 consecutive wrong codes. It also matches `ErrFailedPrecondition` |
| `ErrInvalidArgument` | `InvalidArgument` | A request field failed the server's checks; `Field` names it. A string argument that is not valid UTF-8, or a `TTL` the request's 32-bit field cannot carry, is refused locally with an error that matches it and carries no code (described under [Strings](#strings)) |
| `ErrUnavailable` | `Unavailable` | The server could not be reached, the TLS handshake failed, or the deployment holds more users than its licence allows |
| `ErrAborted` | `Aborted` | A concurrent call on the same user, device or key held a lock too long. Nothing changed; the call may be repeated |
| `ErrDeadlineExceeded` | `DeadlineExceeded` | The call ran past its deadline. It also matches `context.DeadlineExceeded` |
| `ErrCanceled` | `Canceled` | The call was cancelled, or ended or made after `Close`. It also matches `context.Canceled` |
| `ErrInternal` | `Internal` | The server failed |
| `ErrConfiguration` | — | `New` could not build a client, as described under [Configuration](#configuration). It is not a `*StatusError` |

Any other gRPC code is still a `*StatusError` and matches no sentinel.

### StatusError

- `Code` is the gRPC status code.
- `Reason` is the server's reason, an `ErrorReason`, to be compared with the `ErrorReason…` constants, such as `ErrorReasonUserNotFound`. It is `ErrorReasonUnspecified` when the status carries no detail: a transport error, a status gRPC raised itself, or an internal failure answered without one.
- `Message` is the status message.
- `TraceID` is the call's W3C trace ID, 32 hexadecimal characters, when the server attached one. With it, the deployment's operators can find the call in the server's logs.
- `Field` is the request field that failed a check.
- `Subject` is what the refusal refers to, as the call named it: the opaque ID on `USER_NOT_FOUND`, the device ID on `DEVICE_NOT_FOUND`. On `RATE_LIMIT_EXCEEDED` from a per-user limit, and on `CHALLENGE_TOO_SOON`, it is `<relying party ID>:<opaque ID>`; on the limit of `UnlockUserRequestLimits`, it is `unlock_guard:<relying party ID>:<opaque ID>`.
- `AutoExpiresAt` is set on `RATE_LIMIT_EXCEEDED` from a per-user limit and on `CHALLENGE_TOO_SOON`: the time from which the call is admitted again. A repetition before then is refused. It is the zero time when the server sent none.

A `*StatusError` also reads as a gRPC status: `status.Code(err)` and `status.FromError(err)` see its code, its message and every detail the server attached.

### Errors any call can return

The tables under each call list only that call's own errors. Any call can also return these:

| Sentinel | Reason | When |
|---|---|---|
| `ErrUnavailable` | — | The server cannot be reached, or the TLS handshake refused the certificate: a CA the deployment does not use issued it, or it has expired. The handshake fails before any gRPC status exists, so there is no reason |
| `ErrUnavailable` | `LICENSE_USER_CAP_REACHED` | The deployment holds over 110% of its licensed seats. Every call is refused until its operator acts |
| `ErrUnavailable` | `SERVER_UNAVAILABLE` | The server cannot read its own seat counts, so it refuses rather than guess |
| `ErrUnavailable` | `SERVER_UNAVAILABLE` | The server's database did not answer in time, as when it is overloaded. Retry with backoff |
| `ErrUnauthenticated` | `MTLS_CERT_REFUSED` | The certificate passed the handshake but names no relying party the server knows |
| `ErrUnauthenticated` | `MTLS_CERT_EXPIRED` | The certificate expired after the connection opened, as described under [Renewing the certificate](#renewing-the-certificate) |
| `ErrPermissionDenied` | `PERMISSION_DENIED` | The deployment's operator has disabled the relying party |
| `ErrFailedPrecondition` | `LICENSE_EXPIRED` | The deployment's licence expired more than 30 days ago |
| `ErrInvalidArgument` | `INVALID_ARGUMENT` | An ID is malformed: an opaque ID that is not 64 lowercase hexadecimal characters, a device ID that is not a UUID (an empty one included), a permanent ID that is over 256 bytes or not printable ASCII, or a challenge ID that is not a ULID. `Field` names it |
| `ErrAborted` | `SERVER_UNAVAILABLE` | A concurrent call on the same user, device or key held a lock for over 5 seconds. Nothing changed; the call may be repeated |
| `ErrDeadlineExceeded` | — | The call ran past the deadline of its `ctx`, or past 30 seconds, the server's limit for a call that is not a stream |
| `ErrCanceled` | — | `ctx` was cancelled, or the client was closed |
| `ErrInternal` | — | The server failed. The message carries the trace ID: `YDFI_ERROR_SERVER_INTERNAL [<trace ID>]` |
| `ErrInternal` | `SERVER_INTERNAL` | The server could not read the relying party's record to authenticate the call |

The SDK never repeats a call itself.

---

## Limits

Each user has limits of their own on the calls that reach their phone or test their codes. A call that finds a limit spent returns `ErrResourceExhausted` with reason `RATE_LIMIT_EXCEEDED`, and `AutoExpiresAt` is the time from which it is admitted again.

Each limit holds a number of attempts and earns them back one at a time. The deployment's operator chooses the relying party's plan: Standard unless another is set.

| Call | Standard | Conservative | Permissive |
|---|---|---|---|
| `IssueAuthChallenge` | 10, one back every 4 h | 3, one back every 24 h | 20, one back every hour |
| `VerifyUserTOTP` (wrong codes, and the refusals `USER_LOCKED` and `TOTP_SECRET_KEY_UNAVAILABLE`) | 5, one back every 15 min | 5, one back every 30 min | 10, one back every 5 min |
| `IssueEnrollmentInvite` | 5, one back every hour | 3, one back every 4 h | 10, one back every 30 min |
| `IssueRecoveryInvite` | 2, one back every 6 h | 2, one back every 24 h | 5, one back every 2 h |
| `IssueUserTOTPEnrollment` | 10, one back every hour | the same | the same |
| `UnlockUserRequestLimits` | 3, one back every 10 min | the same | the same |

- A limit that runs out refuses for at least 30 minutes, or until it has earned an attempt back if that takes longer.
- An approved challenge restores the user's challenge attempts in full. A denial, a dismissal or an expiry does not.
- `IssueAuthChallenge` returns `ErrChallengeTooSoon` while the user's newest challenge is still open and less than 15 seconds old. That costs no attempt. An answer or an expiry admits the next challenge at once.
- A request that fails validation (`ErrInvalidArgument`) costs no attempt on any call.
- `UnlockUserRequestLimits` restores all of a user's attempts. It has a limit of its own, per user.
- There is no limit on the relying party as a whole.

Other bounds:

| What | Bound |
|---|---|
| Active devices per user | 3 |
| Users per relying party | Set by the deployment's operator (`MAX_USERS_REACHED`) |
| Challenge lifetime (`TTL`) | 30 to 300 seconds, sent in whole seconds; 0 means 60 |
| Invite lifetime (`TTL`) | 60 to 600 seconds, sent in whole seconds; 0 means 300 |
| Challenge context | 16 to 256 bytes, as described under [IssueAuthChallenge](#issueauthchallenge) |
| Invite context | Up to 256 bytes |
| Geofence radius | 50 to 500,000 meters |
| Match code | 0 (off) or 10 to 99 |
| `BulkCreateUsers` count | 1 to 1,000,000 |
| `BulkCreateUsers` idempotency key | 1 to 255 bytes of UTF-8, no NUL; at most 1,000 keys per relying party, each held for 30 days |
| `BanDevice` reason | Up to 512 bytes of UTF-8, no NUL |
| Duration of a call that is not a stream | 30 seconds |
| Size of a request | 64 KiB. A larger request is refused with `ErrResourceExhausted` and no reason, before authentication |

---

## Deadlines

Every call honors its `ctx`: a deadline or a cancellation bounds the call. A call past its deadline returns `ErrDeadlineExceeded`, which also matches `context.DeadlineExceeded`; a cancelled call returns `ErrCanceled`, which also matches `context.Canceled`. The client adds no deadline of its own.

The server ends a call that is not a stream after 30 seconds. It holds an `AwaitChallenge` stream open until the challenge is answered, or until 5 seconds after the challenge expires, when it sends `Expired`. A deadline on a wait is therefore advisable, not required: the challenge's lifetime plus a margin, such as 70 seconds for the default 60, bounds it.

```go
ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
defer cancel()
for frame, err := range client.AwaitChallenge(ctx, challenge.ChallengeID) {
	// ...
}
```

---

## Streaming

Three calls read a server stream and return an iterator, an `iter.Seq2`:

- `ExportUsers` yields each [`User`](#user);
- `BulkCreateUsers` yields the opaque ID of each user;
- `AwaitChallenge` yields each frame of a challenge's wait, a [`ChallengeResult`](#challengeresult).

```go
for user, err := range client.ExportUsers(ctx, "") {
	if err != nil {
		log.Fatal(err)
	}
	// use user
}
```

- Each range over an iterator issues a new call. Ranging over the same iterator twice issues two calls.
- An error is yielded once, and the iteration ends after it.
- The iteration ends without an error when the server ends the stream.
- Leaving the loop early ends the call, as does the end of `ctx`.

---

## Concurrency

A `Client` is safe for concurrent use. One client is built per identity server and shared; one gRPC connection carries every call. One range over an iterator runs in one goroutine; separate ranges are independent calls.

`Close` closes the connection. Calls in flight, and calls made after `Close`, end with `ErrCanceled`. `Close` may be called more than once and from several goroutines: the connection is closed once, and every call returns the result of that close.

---

## API reference

Every method takes a `context.Context` first and honors its deadline and cancellation.

IDs:

- An **opaque ID** names a user: 64 lowercase hexadecimal characters. It is the only handle the server keeps for a user, so the relying party stores it with its own user record. It is opaque.
- A **device ID** names one enrollment of one phone: a UUID.
- A **permanent ID** names the phone itself. It is the same under every relying party and every deployment.
- A **challenge ID** names a challenge: a 26-character ULID.

### Users

#### CreateUser

Creates an anonymous user for the calling relying party.

```go
func (c *Client) CreateUser(ctx context.Context) (string, error)
```

**Returns** the new user's opaque ID.

**Errors**

| Sentinel | Reason | When |
|---|---|---|
| `ErrResourceExhausted` | `MAX_USERS_REACHED` | The relying party has as many users as the operator allows. Deleting a user frees a place at once |

**Behavior**

- Every call creates a new user.
- The server runs at most 4 `CreateUser` calls at once for one relying party. The others wait, and a call that waits past its deadline returns `ErrDeadlineExceeded`. Many users are created with `BulkCreateUsers`.

---

#### BulkCreateUsers

Creates many users in one streamed call, for moving an existing user base onto Ydentifi.

```go
func (c *Client) BulkCreateUsers(ctx context.Context, count uint32, idempotencyKey string) iter.Seq2[string, error]
```

**Parameters**

- `count` — how many users to create: 1 to 1,000,000.
- `idempotencyKey` — a name for this batch, 1 to 255 bytes. A repeated call with the same key never creates a user twice. The same key always carries the same `count`.

**Returns** an iterator over the opaque IDs, as described under [Streaming](#streaming).

**Errors**, yielded by the iterator:

| Sentinel | Reason | When |
|---|---|---|
| `ErrInvalidArgument` | `INVALID_ARGUMENT` | `count` is out of range, the key is empty, too long or holds NUL, or the key was used before with another `count`. `Field` names `count` or `idempotency_key` |
| `ErrResourceExhausted` | `RATE_LIMIT_EXCEEDED` | A new key while the relying party already holds 1,000 keys. Each key is held for 30 days from its first user. A key already held is never refused. `Field` is `idempotency_key`, and the refusal carries no `AutoExpiresAt` |
| `ErrAborted` | `SERVER_UNAVAILABLE` | Another call under the same key holds it. The call may be repeated with the same key |

**Behavior**

- Users are created in chunks of 500.
- A repeated call with the same key first yields the IDs the key already created that still exist, including any that an interrupted call created but never delivered. It then creates what is missing. An ID can therefore be yielded by more than one call, and IDs are kept as a set.
- Reaching the relying party's user cap is not an error: the iteration ends normally after fewer IDs than `count`. Once the operator raises the cap, a repeated call with the same key creates the rest.

---

#### GetUser

Returns one user.

```go
func (c *Client) GetUser(ctx context.Context, opaqueID string) (*User, error)
```

**Returns** the [`User`](#user).

**Errors**

| Sentinel | Reason | When |
|---|---|---|
| `ErrNotFound` | `USER_NOT_FOUND` | No user of the relying party has that opaque ID. Another relying party's user receives the same answer. `Subject` is the opaque ID sent |

---

#### ExportUsers

Streams every user of the relying party, 500 to a page, for exports and for reconciliation with the relying party's own records.

```go
func (c *Client) ExportUsers(ctx context.Context, startAfterID string) iter.Seq2[*User, error]
```

**Parameters**

- `startAfterID` — where the export resumes: `""` starts from the beginning, and an opaque ID the export yielded continues after it.

**Returns** an iterator over the [`User`](#user)s, as described under [Streaming](#streaming).

**Errors**, yielded by the iterator:

| Sentinel | Reason | When |
|---|---|---|
| `ErrInvalidArgument` | `INVALID_ARGUMENT` | `startAfterID` names no user of the relying party, including one deleted since the export yielded it. `Field` is `start_after_user_id`. The export is resumed from the ID before it, or started again from `""` |

**Behavior**

- The order of the users is unspecified.
- The server checks the certificate again before every page, so `ErrUnauthenticated` or `ErrPermissionDenied` can arrive in the middle of the stream.

---

#### UpdateUserStatus

Locks or unlocks a user.

```go
func (c *Client) UpdateUserStatus(ctx context.Context, opaqueID string, status UserStatus) error
```

**Parameters**

- `status` — `UserStatusLocked` or `UserStatusActive`. A locked user is refused challenges, TOTP checks and invites (`USER_LOCKED`).

**Errors**

| Sentinel | Reason | When |
|---|---|---|
| `ErrNotFound` | `USER_NOT_FOUND` | No user of the relying party has that opaque ID. `Subject` is the opaque ID sent |
| `ErrInvalidArgument` | `INVALID_ARGUMENT` | `status` is neither `UserStatusActive` nor `UserStatusLocked` |
| `ErrAborted` | `SERVER_UNAVAILABLE` | A status change or TOTP enrollment for the same user is in flight. The call may be repeated |

**Behavior**

- Setting the status the user already has succeeds and changes nothing.
- Locking a user ends every open challenge of the user as `Expired` and revokes the user's live invites.

---

#### DeleteUser

Deletes a user, with the user's devices and challenges.

```go
func (c *Client) DeleteUser(ctx context.Context, opaqueID string) error
```

**Errors**

| Sentinel | Reason | When |
|---|---|---|
| `ErrNotFound` | `USER_NOT_FOUND` | No user of the relying party has that opaque ID. `Subject` is the opaque ID sent |

**Behavior**

- The bans of the user's devices remain. `UnbanDevice` with `PermanentID` lifts one later.
- An open `AwaitChallenge` on one of the user's challenges ends with `Expired` at the challenge's expiry, at most 5 seconds after it: the deletion itself does not end the wait.
- An opaque ID is never reused.

---

#### UnlockUserRequestLimits

Restores all of a user's attempts on every [per-user limit](#limits).

```go
func (c *Client) UnlockUserRequestLimits(ctx context.Context, opaqueID string) error
```

**Errors**

| Sentinel | Reason | When |
|---|---|---|
| `ErrNotFound` | `USER_NOT_FOUND` | No user of the relying party has that opaque ID. `Subject` is the opaque ID sent |
| `ErrResourceExhausted` | `RATE_LIMIT_EXCEEDED` | This user's unlocks are spent: 3, then one back every 10 minutes, on every plan |

**Behavior**

- It is intended for the end of a completed recovery. A lost phone may have spent the user's challenge attempts on sign-ins it could not answer, and enrolling the new phone does not restore them.
- Before a recovery, it would also lift the limit on unanswered challenges, which is what stops a flood of approval requests.
- It does not unlock TOTP codes locked after 100 wrong codes (`ErrTOTPLocked`). Only a new secret does.

---

### Devices

A user may have 3 active devices. No call returns a device's history; the deployment's server logs hold it.

#### ListDevicesForUser

Lists a user's devices.

```go
func (c *Client) ListDevicesForUser(ctx context.Context, opaqueID string) ([]*Device, error)
```

**Returns** the user's [`Device`](#device)s, in every status: active, inactive and banned. It is empty for a user with no device.

**Errors**

| Sentinel | Reason | When |
|---|---|---|
| `ErrNotFound` | `USER_NOT_FOUND` | No user of the relying party has that opaque ID. `Subject` is the opaque ID sent |

**Behavior**

- Each device carries the permanent ID of its phone. It is the same under every relying party and every deployment, so relying parties that compare their lists can link one handset's users.

---

#### RevokeDevice

Revokes one device. It can no longer sign in or approve, and the user's open challenges end if the device was active.

```go
func (c *Client) RevokeDevice(ctx context.Context, opaqueID, deviceID string) error
```

**Errors**

| Sentinel | Reason | When |
|---|---|---|
| `ErrNotFound` | `DEVICE_NOT_FOUND` | The user has no device with that ID under the relying party. An unknown opaque ID, another user's device and another relying party's all receive the same answer. `Subject` is the device ID sent |

**Behavior**

- The device moves to `DeviceStatusInactive`. It is used again only after the user enrolls it again.
- Revoking a device that is not active succeeds and changes nothing.
- The user's TOTP secret is not replaced: the device's copy keeps producing valid codes. `IssueUserTOTPEnrollment` with `reuseExisting` false, called **after** the revocation, takes it away. A new secret goes to every device the user still has.

---

#### BanDevice

Bans a phone from the relying party: it cannot enroll again under any of the relying party's users.

```go
func (c *Client) BanDevice(ctx context.Context, opaqueID, deviceID, reason string) (int32, error)
```

**Parameters**

- `deviceID` — one of the user's devices. The ban falls on its phone.
- `reason` — the relying party's note on the ban, up to 512 bytes, such as `"reported stolen"`.

**Returns** how many active devices on that phone the ban moved to `DeviceStatusBanned`: 0 or 1, since a phone is active under one of the relying party's users at a time.

**Errors**

| Sentinel | Reason | When |
|---|---|---|
| `ErrNotFound` | `DEVICE_NOT_FOUND` | As for `RevokeDevice` |
| `ErrInvalidArgument` | `INVALID_ARGUMENT` | `reason` is over 512 bytes or holds NUL |

**Behavior**

- The ban is on the phone's permanent ID, not on one enrollment.
- Banning a phone that is already banned succeeds and changes nothing.
- A ban applies to the calling relying party only.
- The user's TOTP secret is not replaced, as for `RevokeDevice`: it is replaced after the ban, not before.

---

#### UnbanDevice

Lifts a ban of the relying party on a phone, named by one of a user's devices or by its permanent ID.

```go
func (c *Client) UnbanDevice(ctx context.Context, req UnbanDeviceRequest) error
```

**Parameters**, in `UnbanDeviceRequest`:

- `OpaqueID` — the user. With `PermanentID`, the server checks only its form and does not look the user up, so the opaque ID of a deleted user is accepted.
- `DeviceID` — one of the user's devices; the ban on its phone is lifted.
- `PermanentID` — the phone's permanent ID, as `ListDevicesForUser` returned it: up to 256 bytes of printable ASCII. After `DeleteUser`, which deletes the user's devices and keeps their bans, it is the only way to name the phone.

Exactly one of `DeviceID` and `PermanentID` is set. The request is sent as given: with both set, or neither, the server refuses it with `ErrInvalidArgument` on the field `device_id`.

**Errors**

| Sentinel | Reason | When |
|---|---|---|
| `ErrNotFound` | `DEVICE_NOT_FOUND` | With `DeviceID`: as for `RevokeDevice` |

**Behavior**

- The banned devices on that phone move to `DeviceStatusInactive`, not to active: the user enrolls the phone again.
- Lifting a ban that does not exist succeeds and changes nothing.

---

### Challenges

A challenge asks the user to approve something on their phone. It is issued with `IssueAuthChallenge`, and its answer is read with `AwaitChallenge`.

#### IssueAuthChallenge

Issues a challenge to the user's phones.

```go
func (c *Client) IssueAuthChallenge(ctx context.Context, req IssueAuthChallengeRequest) (*Challenge, error)
```

**Parameters**, in `IssueAuthChallengeRequest`:

- `OpaqueID` — the user.
- `Context` — **required.** What the user approves, as UTF-8 text the phone shows: 16 to 256 bytes, such as `"Transfer of 1,000 EUR to ACME Corp"`. The user's signature covers it. [The challenge text](#the-challenge-text) lists what is refused.
- `MinStrength` — **required.** The weakest unlock the approval may use: `AuthStrengthDeviceAccess` (biometric or passcode) or `AuthStrengthBiometric` (biometric only). An approval always meets it; a decline is not held to it.
- `TTL` — how long the challenge stays open: 30 to 300 seconds, sent in whole seconds. 0 means 60. A `TTL` below zero, or of 2^32 seconds or more, which the request's 32-bit field cannot carry, is refused before any request is sent, with an error that matches `ErrInvalidArgument` and is not a `*StatusError`.
- `MatchCode` — optional number matching. The relying party shows this number, 10 to 99, on its own screen; the user types it on the phone before approving. 0 turns it off.
- `LocationConstraint` — an optional geofence, described under [LocationConstraint](#locationconstraint).
- `ChallengeID` — optional: a 26-character uppercase ULID that the relying party creates, so that a request whose response was lost can be repeated without creating a second challenge. When it is empty, the server creates the ID.

**Returns** a [`Challenge`](#challenge). `QREncoded` is a link to the challenge, to be rendered as a QR code exactly as given; a phone that scans it opens the challenge. The user's enrolled phones also receive the challenge without a scan.

**Errors**

| Sentinel | Reason | When |
|---|---|---|
| `ErrNotFound` | `USER_NOT_FOUND` | No user of the relying party has that opaque ID. `Subject` is the opaque ID sent |
| `ErrNotFound` | `NO_ACTIVE_DEVICE_FOR_USER` | The user has no active device |
| `ErrFailedPrecondition` | `USER_LOCKED` | The user is locked |
| `ErrFailedPrecondition` | `DEVICE_INCAPABLE` | None of the user's active devices can meet `MinStrength`, according to the capabilities each reported within the last 24 hours. A device that reported only `biometric` is also refused for `AuthStrengthDeviceAccess`; a device whose report is older than 24 hours is never refused |
| `ErrInvalidArgument` | `MIN_STRENGTH_REQUIRED` | `MinStrength` is `AuthStrengthUnspecified`. `Field` is `min_strength` |
| `ErrInvalidArgument` | `INVALID_ARGUMENT` | A field is out of bounds or malformed: `Context` (described below), `TTL`, `MatchCode`, the geofence, or a `ChallengeID` that is not an uppercase ULID. Or `ChallengeID` was already used for a different request. `Field` names it |
| `ErrAlreadyExists` | `CHALLENGE_ALREADY_EXISTS` | `ChallengeID` was already used for this same request: the repetition found the challenge already issued |
| `ErrChallengeTooSoon` | `CHALLENGE_TOO_SOON` | The user's newest challenge is still open and less than 15 seconds old. No attempt was spent. The call is admitted again at `AutoExpiresAt`, or once the user answers |
| `ErrResourceExhausted` | `RATE_LIMIT_EXCEEDED` | The user's challenge attempts are spent, as listed under [Limits](#limits) |

Each challenge issued costs one of the user's attempts. So do these refusals: `USER_LOCKED`, `DEVICE_INCAPABLE`, and a reused `ChallengeID` (`CHALLENGE_ALREADY_EXISTS`, or `INVALID_ARGUMENT` for a different request). An unknown user, a user with no active device, `ErrChallengeTooSoon` and a request that fails validation cost none.

**Behavior**

- A reused `ChallengeID` is compared with the challenge it names on the user, `Context`, `MinStrength`, `MatchCode` and the geofence, not on `TTL`.
- A phone enrolled after the challenge was issued cannot answer it.
- An approval with an unlock weaker than `MinStrength` is refused to the phone and does not end the challenge, which stays open until another answer or its expiry.
- An approval that fails both the match code and the geofence ends `Rejected` with `VerificationFailureWrongMatchCode`.

**Accessibility.** `AuthStrengthBiometric` accepts a biometric only, with no passcode. Some people cannot use one, for medical or physical reasons, or for a while after an injury. For those users a flag on the relying party's own user record selects `AuthStrengthDeviceAccess`, which accepts the passcode. Ydentifi never sees the flag.

##### The challenge text

`Context` is shown to the user, and the user's signature commits to its bytes. The server therefore refuses text a phone might show as something other than its bytes. It holds 16 to 256 bytes, not counting white space and characters that draw a blank, and at least one letter, digit or emoji. Judged against Unicode 17.0, it is refused if it holds:

- bytes that are not UTF-8, or text not in Unicode NFC;
- a control character, tabs and line breaks included, or U+2028 or U+2029;
- white space at either end or two in a row, or any space but U+0020, U+00A0, U+202F and U+3000;
- a private-use, noncharacter or unassigned code point, or U+FFFC;
- a bidirectional formatting character: the embeddings, overrides and isolates, and the marks U+200E, U+200F and U+061C;
- a zero-width joiner or non-joiner outside an emoji sequence Unicode recommends or the words of a script it shapes;
- a variation selector outside a sequence that selects a glyph, or any ideographic variation selector (U+E0100–U+E01EF);
- a tag character outside the flags of England, Scotland and Wales, or a regional indicator outside a recommended flag;
- any other invisible or formatting character;
- a character that draws a blank though it is not a space (U+2800, U+303F, U+1D159, U+13441, U+13442, U+1DA7F, U+1DA80, U+16FE4);
- a combining mark with nothing to mark, or more than six on one character;
- an overlay or enclosing mark (canonical combining class 1, such as the strokes U+0334–U+0338, and general category Me, such as U+20DD–U+20E0), which can strike out an amount the signature still commits to. U+20E3 at the end of a keycap emoji Unicode recommends is allowed.

The refusal names the character and its byte offset.

Real text uses some of what is refused, so it is normalized or stripped before issuance:

- an emoji selector after an emoji that already shows as one (a star or check mark followed by U+FE0F), and a keycap without its U+FE0F;
- soft hyphens, and the zero-width space Thai, Khmer and Shan put between words;
- a zero-width non-joiner where it breaks no join (Persian after alef, Sorani at a word's end);
- right-to-left marks and isolates around numbers and names;
- ideographic variation selectors in Japanese names;
- the Bassa Vah tone marks, some Vedic accents and the Church Slavonic number signs;
- tabs, line breaks, and doubled, leading or trailing spaces, and other space characters;
- the blank Braille pattern between Braille words, which is replaced by a space;
- text not in NFC: decomposed letters, marks in another order (such as Arabic shadda before its vowel, or pointed Hebrew), and Devanagari, Bengali, Gurmukhi and Oriya letters in their precomposed nukta forms.

The check is partial. It lets through:

- a space or a no-break space in each gap between words (about one bit a gap);
- a joiner after a virama in scripts whose fonts draw the same either way, such as Tamil and Sinhala (about 51 bits in 256 bytes);
- standardized variation selectors on CJK ideographs (about 42 bits), and the selector that gives a Myanmar letter its dotted form (about one bit a letter);
- up to six marks on each letter;
- emoji sequences newer than a phone's fonts, which it shows as their parts;
- look-alike letters from other scripts.

Text that mixes right-to-left and left-to-right writing can display in another order than its bytes even without any of these characters, and nothing refuses that.

---

#### AwaitChallenge

Streams the frames of a challenge's wait, up to its outcome.

```go
func (c *Client) AwaitChallenge(ctx context.Context, challengeID string) iter.Seq2[*ChallengeResult, error]
```

**Returns** an iterator over the [`ChallengeResult`](#challengeresult) frames, as described under [Streaming](#streaming). The first frame is the challenge's current state: `Pending`, `Delivered`, or already its outcome. The server ends the stream after the first frame whose status ends the challenge, as `status.IsTerminal()` reports: `Approved`, `Denied`, `Rejected`, `Expired`, `Superseded` or `Dismissed`.

```go
for frame, err := range client.AwaitChallenge(ctx, challenge.ChallengeID) {
	if err != nil {
		return err
	}
	if frame.Status.IsTerminal() {
		log.Println("outcome:", frame.Status)
	}
}
```

**Errors**, yielded by the iterator:

| Sentinel | Reason | When |
|---|---|---|
| `ErrNotFound` | `CHALLENGE_NOT_FOUND` | The relying party has no challenge with that ID. `Subject` is the ID sent |
| `ErrInvalidArgument` | `INVALID_ARGUMENT` | `challengeID` is not a ULID. `Field` is `challenge_id` |

**Behavior**

- The wait may begin before or after the user answers. An answer given before the stream opened arrives as its first frame.
- After the first frame, the stream reports only the outcome: a delivery to the phone after the stream opened is not streamed.
- When no answer comes, the server ends the stream with `Expired` at most 5 seconds after the challenge expires. A deadline on `ctx` is advisable, as described under [Deadlines](#deadlines).
- A second wait on the same challenge, served by the same server, ends the first with `Superseded`.
- If the user is deleted during the wait, the wait ends with `Expired` at the challenge's expiry, at most 5 seconds after it.
- A challenge ID in lower case is answered with `CHALLENGE_NOT_FOUND`, although `IssueAuthChallenge` refuses one with `INVALID_ARGUMENT`.
- `Signature` is the phone's signature over the challenge. The server checked it before it declared `Approved`. No call returns the phone's key, so it cannot be checked independently; it is kept as a record.

---

#### ListActiveChallenges

Lists a user's open challenges: those pending or delivered, not yet ended.

```go
func (c *Client) ListActiveChallenges(ctx context.Context, opaqueID string) ([]*ActiveChallenge, error)
```

**Returns** the user's [`ActiveChallenge`](#activechallenge)s, possibly none.

**Errors**

| Sentinel | Reason | When |
|---|---|---|
| `ErrNotFound` | `USER_NOT_FOUND` | No user of the relying party has that opaque ID. `Subject` is the opaque ID sent |

**Behavior**

- A challenge past its expiry is not listed: the call ends it as `Expired`.

---

### TOTP

Every user has a TOTP secret from the moment the user is created, and the user's enrolled phones receive it. Codes are 6 digits, a new one every 30 seconds, SHA-1. The secret may also be given to a standard authenticator app.

#### IssueUserTOTPEnrollment

Returns the user's TOTP secret, or replaces it with a new one.

```go
func (c *Client) IssueUserTOTPEnrollment(ctx context.Context, opaqueID string, reuseExisting bool) (*TOTPEnrollment, error)
```

**Parameters**

- `reuseExisting` — `true` returns the current secret. `false` replaces it with a new one, which also unlocks codes locked after 100 wrong codes.

**Returns** a [`TOTPEnrollment`](#totpenrollment): the secret in base32, its `otpauth://` URL, and that URL as a 255×255 QR code PNG. The URL's label may be changed, for example to show the user's name in an authenticator app.

**Errors**

| Sentinel | Reason | When |
|---|---|---|
| `ErrNotFound` | `USER_NOT_FOUND` | No user of the relying party has that opaque ID. `Subject` is the opaque ID sent |
| `ErrFailedPrecondition` | `USER_LOCKED` | The user is locked |
| `ErrFailedPrecondition` | `TOTP_SECRET_KEY_UNAVAILABLE` | `reuseExisting` is `true` and the stored secret cannot be read. A call with `false` issues a new one |
| `ErrResourceExhausted` | `RATE_LIMIT_EXCEEDED` | The user's enrollment attempts are spent: 10, then one back every hour. Every call spends one |
| `ErrAborted` | `SERVER_UNAVAILABLE` | A status change or TOTP enrollment for the same user is in flight. The call may be repeated |

**Behavior**

- A new secret goes to every device the user still has.
- A secret is taken away from a phone in this order: the phone is removed (`RevokeDevice`, `BanDevice` or `IssueRecoveryInvite`); this method is called with `reuseExisting` false; the user is then locked, if required. A phone removed after the new secret was issued may already hold it. Until this call, the old secret's codes still work, so the calls follow one another directly. A locked user is refused, which is why the lock comes last.

---

#### VerifyUserTOTP

Checks a TOTP code the user typed.

```go
func (c *Client) VerifyUserTOTP(ctx context.Context, opaqueID, code string) (bool, error)
```

**Parameters**

- `code` — exactly 6 ASCII digits.

**Returns** `true` when the code is valid. A code is checked against the current 30-second step and the steps on either side, about 90 seconds in all, and is accepted only if its step is later than the step of the last code accepted for the same secret. **A code therefore works once**: a code already accepted, or any code of an earlier or the same step, returns `false`, as a wrong code does.

**Errors**

| Sentinel | Reason | When |
|---|---|---|
| `ErrNotFound` | `USER_NOT_FOUND` | No user of the relying party has that opaque ID. `Subject` is the opaque ID sent |
| `ErrInvalidArgument` | `INVALID_ARGUMENT` | `code` is not 6 ASCII digits. `Field` is `totp_code` |
| `ErrFailedPrecondition` | `USER_LOCKED` | The user is locked. The refusal spends an attempt |
| `ErrTOTPLocked` | `TOTP_LOCKED` | The user's codes are locked after 100 consecutive wrong codes |
| `ErrFailedPrecondition` | `TOTP_SECRET_KEY_UNAVAILABLE` | The stored secret cannot be read; `IssueUserTOTPEnrollment` issues a new one. The refusal spends an attempt |
| `ErrResourceExhausted` | `RATE_LIMIT_EXCEEDED` | The user's attempts are spent, as listed under [Limits](#limits) |
| `ErrAborted` | `SERVER_UNAVAILABLE` | Another `VerifyUserTOTP` for the same user is in flight. The call may be repeated |

**Behavior**

- A wrong code returns `(false, nil)` and spends an attempt. A valid code spends none.
- 100 consecutive wrong codes lock the user's codes. The 100th is checked and charged like any other, and returns `ErrTOTPLocked`. Every code after it returns `ErrTOTPLocked` without being checked or charged, a valid one too. A valid code before the 100th starts the count again.
- Only codes lock. The user stays active, and challenges still work. `User.TOTPLocked` shows the lock. Only `IssueUserTOTPEnrollment` with `reuseExisting` false lifts it.

---

### Enrollment and recovery

A user has one live invite at a time. Issuing an invite, of either kind, revokes the user's previous one.

#### IssueEnrollmentInvite

Issues an invite that the user scans with the Ydentifi app to enroll a phone.

```go
func (c *Client) IssueEnrollmentInvite(ctx context.Context, req IssueEnrollmentInviteRequest) (*EnrollmentInvite, error)
```

**Parameters**, in `IssueEnrollmentInviteRequest`:

- `OpaqueID` — the user.
- `TTL` — how long the invite can be scanned: 60 to 600 seconds, sent in whole seconds. 0 means 300. A `TTL` below zero, or of 2^32 seconds or more, which the request's 32-bit field cannot carry, is refused before any request is sent, with an error that matches `ErrInvalidArgument` and is not a `*StatusError`.
- `Context` — optional, up to 256 bytes. The phone does not show it, and the enrollment does not sign it.

**Returns** an [`EnrollmentInvite`](#enrollmentinvite--recoveryinvite). `QRPayload` is shown as a QR code.

**Errors**

| Sentinel | Reason | When |
|---|---|---|
| `ErrNotFound` | `USER_NOT_FOUND` | No user of the relying party has that opaque ID. `Subject` is the opaque ID sent |
| `ErrFailedPrecondition` | `USER_LOCKED` | The user is locked |
| `ErrDeviceLimitReached` | `MAX_DEVICES_REACHED` | The user already has 3 active devices. No invite was issued, and an attempt was spent. The user's devices are listed, the user (once authenticated) chooses one to remove, it is revoked, and the invite is issued again |
| `ErrInvalidArgument` | `INVALID_ARGUMENT` | `TTL` or `Context` is out of bounds |
| `ErrResourceExhausted` | `RATE_LIMIT_EXCEEDED` | The user's invite attempts are spent, as listed under [Limits](#limits) |

**Behavior**

- An invite enrolls one phone, once.
- Once the phone has claimed the invite, it has 2 more minutes to finish enrolling, even past the invite's expiry.

---

#### IssueRecoveryInvite

Revokes all of a user's active devices and issues an invite to enroll a new phone, for a user who has lost their phone.

```go
func (c *Client) IssueRecoveryInvite(ctx context.Context, req IssueRecoveryInviteRequest) (*RecoveryInvite, error)
```

**Parameters**, in `IssueRecoveryInviteRequest`: the same as for `IssueEnrollmentInvite`.

**Returns** a [`RecoveryInvite`](#enrollmentinvite--recoveryinvite): an invite, and `RevokedDeviceCount`, how many devices it revoked.

**Errors**

| Sentinel | Reason | When |
|---|---|---|
| `ErrNotFound` | `USER_NOT_FOUND` | No user of the relying party has that opaque ID. `Subject` is the opaque ID sent |
| `ErrFailedPrecondition` | `USER_LOCKED` | The user is locked |
| `ErrInvalidArgument` | `INVALID_ARGUMENT` | `TTL` or `Context` is out of bounds |
| `ErrResourceExhausted` | `RATE_LIMIT_EXCEEDED` | The user's recovery attempts are spent, as listed under [Limits](#limits) |

**Behavior**

- **It revokes every active device of the user,** in the same step as it issues the invite, and ends every open challenge of the user as `Expired`. None of the revoked devices can sign in or approve again.
- **The server takes the call as the authority.** The relying party verifies, out of band, that the person is the user before the call.
- The revoked phones keep their copy of the TOTP secret, and the new phone receives the same secret. When a lost phone may be in someone else's hands, `IssueUserTOTPEnrollment` with `reuseExisting` false follows this call.
- After the recovery completes, `UnlockUserRequestLimits` restores the challenge attempts the lost phone spent.

---

## Types

Every enum below has a `String` method that gives the value's name, such as `"APPROVED"` for `ChallengeStatusApproved`: the same name the other Ydentifi SDKs print. A value newer than this SDK prints as `UNKNOWN_<n>`.

### User

```go
type User struct {
	OpaqueID            string
	Status              UserStatus
	CreatedAt           time.Time
	LastAuthenticatedAt time.Time // a UTC day, at midnight; zero until the first
	LastActivityAt      time.Time // a UTC day, at midnight; zero until the first
	TOTPLocked          bool      // codes locked after 100 consecutive wrong codes
}
```

`LastAuthenticatedAt` and `LastActivityAt` hold the day only, not the time.

### UserStatus

```go
const (
	UserStatusUnspecified UserStatus = 0
	UserStatusActive      UserStatus = 1
	UserStatusLocked      UserStatus = 2
)
```

### Device

```go
type Device struct {
	DeviceID            string         // one enrollment of one phone
	PermanentID         string         // the phone itself; the target of a ban
	Platform            DevicePlatform
	Status              DeviceStatus
	CreatedAt           time.Time
	LastAuthenticatedAt time.Time // a UTC day, at midnight; zero until the first
	Name                string
	Model               string // what the phone declared it is, such as "iPhone17,4"; unchecked
}
```

### DevicePlatform

```go
const (
	DevicePlatformUnspecified DevicePlatform = 0
	DevicePlatformIOS         DevicePlatform = 1
	DevicePlatformAndroid     DevicePlatform = 2
)
```

### DeviceStatus

```go
const (
	DeviceStatusUnspecified DeviceStatus = 0
	DeviceStatusActive      DeviceStatus = 1
	DeviceStatusInactive    DeviceStatus = 3 // revoked or replaced
	DeviceStatusBanned      DeviceStatus = 4
)
```

### UnbanDeviceRequest

```go
type UnbanDeviceRequest struct {
	OpaqueID    string
	DeviceID    string // or
	PermanentID string
}
```

### Challenge

```go
type Challenge struct {
	ChallengeID string
	QREncoded   string // rendered as a QR code, exactly as given
	ExpiresAt   time.Time
}
```

### ChallengeResult

```go
type ChallengeResult struct {
	Status     ChallengeStatus     // what happened
	Expression ChallengeExpression // what the user answered
	Signature  []byte              // set on Approved, Denied and Rejected

	DeclineReason       DeclineReason       // set only when Status is Denied
	VerificationFailure VerificationFailure // set only when Status is Rejected

	LocationResult *LocationResult // set only when the phone reported a location; nil otherwise
	EmittedAt      time.Time

	AuthStrength AuthStrength // the unlock the phone used; meets MinStrength only on Approved
}
```

### ChallengeStatus

```go
const (
	ChallengeStatusUnspecified ChallengeStatus = 0
	ChallengeStatusPending     ChallengeStatus = 1
	ChallengeStatusDelivered   ChallengeStatus = 2
	ChallengeStatusApproved    ChallengeStatus = 3 // ends the challenge
	ChallengeStatusDenied      ChallengeStatus = 4 // ends it: the user refused
	ChallengeStatusExpired     ChallengeStatus = 5 // ends it
	ChallengeStatusSuperseded  ChallengeStatus = 6 // ends it
	ChallengeStatusDismissed   ChallengeStatus = 7 // ends it
	ChallengeStatusRejected    ChallengeStatus = 8 // ends it: the user agreed, a check refused
)
```

`status.IsTerminal()` reports whether a status ends the challenge.

### ChallengeExpression / DeclineReason / VerificationFailure

```go
const (
	ChallengeExpressionUnspecified ChallengeExpression = 0
	ChallengeExpressionApproved    ChallengeExpression = 1
	ChallengeExpressionDeclined    ChallengeExpression = 2
	ChallengeExpressionDismissed   ChallengeExpression = 3
)

const (
	DeclineReasonUnspecified     DeclineReason = 0
	DeclineReasonNotMe           DeclineReason = 1
	DeclineReasonSecurityConcern DeclineReason = 2
	DeclineReasonWrongDetails    DeclineReason = 3
	DeclineReasonCancelled       DeclineReason = 4
)

const (
	VerificationFailureUnspecified      VerificationFailure = 0
	VerificationFailureLocationMismatch VerificationFailure = 1
	VerificationFailureWrongMatchCode   VerificationFailure = 2
)
```

### Distinguishing a refusal from a failed check

`Status` is what happened. `Expression` is what the user answered. They usually agree, and differ in one case: the user approves and a check refuses the approval. That arrives as `Rejected`, with expression `Approved`.

```go
switch result.Status {
case ydentifi.ChallengeStatusApproved:
	// access is granted
case ydentifi.ChallengeStatusDenied:
	log.Println(result.DeclineReason) // the reason the user gave
case ydentifi.ChallengeStatusRejected:
	log.Println(result.VerificationFailure) // the check that refused
}
```

Only `Approved` grants access, so a branch on `Status` alone is safe. The other fields give an accurate record.

`Rejected` with `VerificationFailureWrongMatchCode` calls for action. A user who approves and types a number that was not on the relying party's screen is what an approval driven from another session looks like, which is what number matching exists to detect. Recording it as a decline by the user records the opposite of what happened.

### AuthStrength

```go
const (
	AuthStrengthUnspecified  AuthStrength = 0 // refused as a MinStrength
	AuthStrengthDeviceAccess AuthStrength = 1 // biometric or passcode
	AuthStrengthBiometric    AuthStrength = 2 // biometric only
)
```

### ActiveChallenge

```go
type ActiveChallenge struct {
	ChallengeID        string
	Status             ChallengeStatus // Pending or Delivered
	Context            []byte
	LocationConstraint *LocationConstraint
	IssuedAt           time.Time
	ExpiresAt          time.Time
	DeliveredAt        time.Time // zero until delivered
}
```

### LocationConstraint

```go
type LocationConstraint struct {
	Latitude     float64 // -90 to 90
	Longitude    float64 // -180 to 180
	RadiusMeters uint32  // 50 to 500,000
	Enforcement  LocationEnforcement
}

const (
	LocationEnforcementUnspecified LocationEnforcement = 0 // refused
	LocationEnforcementAdvisory    LocationEnforcement = 1 // reported, not enforced
	LocationEnforcementRequired    LocationEnforcement = 2 // outside it, an approval is Rejected
)
```

`Enforcement` is always set: the server refuses `LocationEnforcementUnspecified`.

### LocationResult

```go
type LocationResult struct {
	Bucket   LocationBucket
	Accuracy LocationAccuracy
}

const (
	LocationBucketUnspecified  LocationBucket = 0
	LocationBucketWithinRadius LocationBucket = 1
	LocationBucketNear         LocationBucket = 2
	LocationBucketFar          LocationBucket = 3
	LocationBucketUnavailable  LocationBucket = 4
	LocationBucketDeniedByUser LocationBucket = 5
)

const (
	LocationAccuracyUnspecified LocationAccuracy = 0
	LocationAccuracyHigh        LocationAccuracy = 1
	LocationAccuracyMedium      LocationAccuracy = 2
	LocationAccuracyLow         LocationAccuracy = 3
)
```

The phone checks the constraint itself and reports only a bucket and an accuracy class, with an approval. The result carries no coordinates, and it is nil on a decline, a dismissal, an expiry, and an approval without a reported location.

### EnrollmentInvite / RecoveryInvite

```go
type EnrollmentInvite struct {
	InviteToken []byte
	QRPayload   []byte // shown as a QR code
	ExpiresAt   time.Time
}

type RecoveryInvite struct {
	InviteToken        []byte
	QRPayload          []byte
	ExpiresAt          time.Time
	RevokedDeviceCount uint32
}
```

`InviteToken` and `QRPayload` are secrets: whoever holds them can enroll a phone for the user. An invite printed with `fmt` or `log`, or passed to `slog` as a value of its own, shows them as their length only. The fields read as normal, and `encoding/json` is unchanged, so `slog`'s JSON handler prints them in full when the invite is inside a struct, slice or map.

### TOTPEnrollment

```go
type TOTPEnrollment struct {
	QRCodePNGBase64 string // the otpauth:// URL as a QR code, a base64 PNG
	TOTPURL         string // otpauth://totp/...
	SecretBase32    string // for users who type it in
}
```

All three fields carry the TOTP secret and are not to be logged or stored in plain text. An enrollment printed with `fmt` or `log`, or passed to `slog` as a value of its own, shows them as their length only. The fields read as normal, and `encoding/json` is unchanged, so `slog`'s JSON handler prints them in full when the enrollment is inside a struct, slice or map.

### StatusError

```go
type StatusError struct {
	Code          codes.Code
	Reason        ErrorReason
	Message       string
	TraceID       string
	Field         string
	Subject       string
	AutoExpiresAt time.Time
}

func (e *StatusError) GRPCStatus() *status.Status
```

The fields are described under [StatusError](#statuserror) in Error handling. `ErrorReason` has a constant for every reason of the protocol, such as `ErrorReasonUserNotFound`; its `String` method gives the reason's name, such as `"USER_NOT_FOUND"`.

---

## Version

```go
ydentifi.Version // "0.1.3"
```

Versions are 0.x: a minor version may change the API.

---

## Examples

[example_test.go](./example_test.go) holds an example for every method.
