//go:build unix

package ydentifi

// The SDK-behaviour cases that need a FIFO or a Unix socket.

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// newReturns runs New and waits up to limit for it to return. A New that
// is still reading a FIFO is released by opening the FIFO for writing
// until it returns, and the wait is reported as a failure.
func newReturns(t *testing.T, limit time.Duration, fifos []string, opts ...Option) (*Client, error) {
	t.Helper()
	type result struct {
		c   *Client
		err error
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		c, err := New(opts...)
		done <- result{c, err}
	}()
	select {
	case r := <-done:
		return r.c, r.err
	case <-time.After(limit):
	}
	for {
		for _, fifo := range fifos {
			// A writer that opens and closes gives the blocked reader an
			// empty file.
			if f, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				if err := f.Close(); err != nil {
					t.Error(err)
				}
			}
		}
		select {
		case r := <-done:
			t.Errorf("New returned after %v, once a FIFO it read was given a writer; want it to return at once", time.Since(start).Round(time.Millisecond))
			return r.c, r.err
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// SDK-008: a certificate, key or CA file that cannot be used is refused by
// New, which names it by its base name only and returns at once on a FIFO.
func TestSDK008_FilesThatCannotBeUsed(t *testing.T) {
	isolateFromEnv(t)
	certPEM, keyPEM := validPair(t, "rp")
	certFile, keyFile := writePair(t, t.TempDir(), certPEM, keyPEM)
	dir := filepath.Join(t.TempDir(), "tenant-a")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	kinds := []struct {
		name string
		make func(path string) error
	}{
		{"a path that does not exist", func(string) error { return nil }},
		{"a directory", func(path string) error { return os.Mkdir(path, 0o700) }},
		{"a FIFO", func(path string) error { return syscall.Mkfifo(path, 0o600) }},
		{"a file without read permission", func(path string) error { return os.WriteFile(path, certPEM, 0o000) }},
	}
	roles := []struct {
		name string
		opts func(path string) []Option
	}{
		{"cert", func(path string) []Option { return []Option{WithCertFiles(path, keyFile)} }},
		{"key", func(path string) []Option { return []Option{WithCertFiles(certFile, path)} }},
		{"ca", func(path string) []Option { return []Option{WithCertFiles(certFile, keyFile), WithCAFile(path)} }},
	}
	for i, kind := range kinds {
		for _, role := range roles {
			t.Run(kind.name+" as the "+role.name, func(t *testing.T) {
				if kind.name == "a file without read permission" && os.Geteuid() == 0 {
					t.Skip("the superuser reads a file whatever its permission bits")
				}
				path := filepath.Join(dir, role.name+"-"+string(rune('a'+i))+".pem")
				if err := kind.make(path); err != nil {
					t.Fatal(err)
				}
				c, err := newReturns(t, 2*time.Second, []string{path}, append(role.opts(path), WithServerAddr(closedAddr))...)
				wantConfigErr(t, kind.name, c, err)
				if t.Failed() {
					return
				}
				if msg := err.Error(); !strings.Contains(msg, filepath.Base(path)) || strings.Contains(msg, dir) {
					t.Fatalf("New: %q; want the file named by its base name %s and no directory", msg, filepath.Base(path))
				}
			})
		}
	}
}

// SDK-032: a pair in the files that cannot be used is refused at each TLS
// handshake, and the certificate in use is presented again. Each problem is
// logged once while it lasts, at Warn, naming the files by their base names
// only; a problem that returns after a usable pair is logged again. A FIFO
// in place of the certificate is refused at once. The TLS hook is called
// directly, so no server is needed.
func TestSDK032_EachProblemIsLoggedOnceWhileItLasts(t *testing.T) {
	isolateFromEnv(t)
	dir := filepath.Join(t.TempDir(), "tenant-a")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	certA, keyA := validPair(t, "rp-a")
	certFile, keyFile := writePair(t, dir, certA, keyA)
	log := &warnings{}
	c, err := New(WithServerAddr(closedAddr), WithCertFiles(certFile, keyFile), WithCAFile(certFile), WithLogger(slog.New(log)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	// handshakes calls the hook n times, each of which is to present rp-a
	// within a second. A hook still reading a FIFO is released by opening
	// the FIFO for writing, and the wait is reported as a failure.
	handshakes := func(what string, n int) {
		t.Helper()
		for range n {
			done := make(chan string, 1)
			go func() {
				cert, err := c.clientCertificate(nil)
				if err != nil {
					done <- err.Error()
					return
				}
				done <- cert.Leaf.Subject.CommonName
			}()
			var got string
			select {
			case got = <-done:
			case <-time.After(time.Second):
				t.Errorf("%s: the hook did not return within 1s", what)
				for got == "" {
					if f, err := os.OpenFile(certFile, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
						if err := f.Close(); err != nil {
							t.Errorf("close the FIFO's writer: %v", err)
						}
					}
					select {
					case got = <-done:
					case <-time.After(50 * time.Millisecond):
					}
				}
			}
			if got != "rp-a" {
				t.Errorf("%s: presented %q; want rp-a, the certificate in use", what, got)
			}
		}
	}
	// wantLogged checks the warnings logged since from: one that holds
	// reason, or none when reason is empty.
	wantLogged := func(what string, from int, reason string) {
		t.Helper()
		lines := log.lines[from:]
		if reason == "" {
			if len(lines) != 0 {
				t.Errorf("%s: logged %q; want nothing", what, lines)
			}
			return
		}
		if len(lines) != 1 {
			t.Errorf("%s: logged %q; want one warning", what, lines)
			return
		}
		line := lines[0]
		if !strings.HasPrefix(line, "WARN ") || !strings.Contains(line, reason) ||
			!strings.Contains(line, "cert=rp.crt") || !strings.Contains(line, "key=rp.key") || strings.Contains(line, dir) {
			t.Errorf("%s: logged %q; want a warning that holds %q and names the files by their base names only", what, line, reason)
		}
	}

	now := time.Now()
	expired, expiredKey := selfSigned(t, "rp-expired", now.Add(-2*time.Hour), now.Add(-time.Hour))
	_, keyB := validPair(t, "rp-b")
	steps := []struct {
		what   string
		write  func()
		reason string
	}{
		{"an expired pair", func() { writePair(t, dir, expired, expiredKey) }, "rp.crt expired at"},
		{"the usable pair again", func() { writePair(t, dir, certA, keyA) }, ""},
		{"the expired pair after the usable one", func() { writePair(t, dir, expired, expiredKey) }, "rp.crt expired at"},
		{"a key that is not the certificate's", func() { writePair(t, dir, certA, keyB) }, "parse the certificate and key"},
		{"a FIFO in place of the certificate", func() {
			tmp := filepath.Join(dir, ".tmp-fifo")
			if err := syscall.Mkfifo(tmp, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(tmp, certFile); err != nil {
				t.Fatal(err)
			}
		}, "read rp.crt: not a regular file"},
		{"the usable pair at the end", func() {
			if err := os.Remove(certFile); err != nil {
				t.Fatal(err)
			}
			writePair(t, dir, certA, keyA)
		}, ""},
	}
	for _, step := range steps {
		from := len(log.lines)
		step.write()
		handshakes(step.what, 3)
		wantLogged(step.what, from, step.reason)
	}
}

// SDK-016: the address is resolved through DNS. unix:443 names the host
// unix and the port 443, never a local socket: a Unix socket named 443 in
// the working directory receives no connection, and the call fails with
// ErrUnavailable.
func TestSDK016_TheAddressIsResolvedThroughDNS(t *testing.T) {
	isolateFromEnv(t)
	t.Chdir(t.TempDir())
	ln, err := net.Listen("unix", "443")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := ln.Close(); err != nil {
			t.Error(err)
		}
	}()
	certPEM, keyPEM := validPair(t, "rp")
	c, err := New(WithServerAddr("unix:443"), WithCert(certPEM, keyPEM), WithCA(certPEM))
	if err != nil {
		t.Fatalf("New: %v; want a client", err)
	}
	defer func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err = c.GetUser(ctx, "00000000000000000000000000000000000000000000000000000000000000ff")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("GetUser: %v; want ErrUnavailable", err)
	}
	if err := ln.(*net.UnixListener).SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if conn, err := ln.Accept(); err == nil {
		t.Fatalf("the Unix socket named 443 received a connection (close: %v)", conn.Close())
	} else if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Accept: %v", err)
	}
}
