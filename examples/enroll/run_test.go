package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
)

// These tests replace loadOrCreateSigner with in-memory fakes. No CNG key is
// created, opened or deleted, and enrollment never reaches the network: the
// OTT JWT fixture is malformed on purpose.

type fakeSigner struct {
	key      *ecdsa.PrivateKey
	closeErr error
	closed   int
}

func (f *fakeSigner) Public() crypto.PublicKey { return &f.key.PublicKey }

func (f *fakeSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return f.key.Sign(rand.Reader, digest, opts)
}

func (f *fakeSigner) Close() error {
	f.closed++
	return f.closeErr
}

func newFakeSigner(t *testing.T) *fakeSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeSigner{key: key}
}

func stubLoadOrCreate(t *testing.T, fn func(string) (windowscng.Signer, error)) *[]string {
	t.Helper()
	var calls []string
	orig := loadOrCreateSigner
	loadOrCreateSigner = func(name string) (windowscng.Signer, error) {
		calls = append(calls, name)
		return fn(name)
	}
	t.Cleanup(func() { loadOrCreateSigner = orig })
	return &calls
}

const runKeyName = "Keppin.Secret.Key"

// runFixture writes a protected-looking JWT file and returns it together with a
// not-yet-existing output path in a fresh temporary directory.
func runFixture(t *testing.T) (jwtPath, output string) {
	t.Helper()
	dir := t.TempDir()
	jwtPath = filepath.Join(dir, "ott.jwt")
	if err := os.WriteFile(jwtPath, []byte("TOKEN_SECRET.invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return jwtPath, filepath.Join(dir, "identity.json")
}

func assertOutputRemoved(t *testing.T, output string) {
	t.Helper()
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reserved output must be removed before a successful enrollment, stat err=%v", err)
	}
}

// TestRunLoadOrCreateRollbackSucceededStaysGeneric uses the v0.2.2 error shape
// for a newly created key that failed after creation and was deleted again
// (cleanup succeeded): the operator gets the generic safe error.
func TestRunLoadOrCreateRollbackSucceededStaysGeneric(t *testing.T) {
	calls := stubLoadOrCreate(t, func(string) (windowscng.Signer, error) {
		return nil, fmt.Errorf("%w (the key created by this call was deleted)", syntheticNative())
	})
	jwtPath, output := runFixture(t)

	err := run(jwtPath, runKeyName, output)
	assertGenericError(t, err)
	assertOutputRemoved(t, output)
	if len(*calls) != 1 || (*calls)[0] != runKeyName {
		t.Fatalf("LoadOrCreate calls = %q, want exactly [%s]", *calls, runKeyName)
	}
}

func TestRunInvalidKeyNameNeverLoadsOrCreates(t *testing.T) {
	calls := stubLoadOrCreate(t, func(string) (windowscng.Signer, error) {
		t.Fatal("LoadOrCreate reached for an invalid key name")
		return nil, nil
	})
	jwtPath, output := runFixture(t)
	if err := run(jwtPath, "a?b", output); err == nil {
		t.Fatal("invalid key name accepted")
	}
	if len(*calls) != 0 {
		t.Fatal("LoadOrCreate called for an invalid key name")
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("output reserved for an invalid key name")
	}
}

// TestRunSetupSignerClosedOnceAndEnrollmentFailsSafely covers the ordinary
// path up to the network boundary: after a successful LoadOrCreate, run
// closes the setup signer exactly once and the failure comes from the
// enrollment stage (malformed JWT on Windows, platform check elsewhere)
// without disclosing the token. It checks the outcome after run returns; the
// Close-before-Enroll order is fixed by run's straight-line code and is not
// observed here, since enrollcng.Enroll has no injection point.
func TestRunSetupSignerClosedOnceAndEnrollmentFailsSafely(t *testing.T) {
	fake := newFakeSigner(t)
	stubLoadOrCreate(t, func(string) (windowscng.Signer, error) { return fake, nil })
	jwtPath, output := runFixture(t)

	err := run(jwtPath, runKeyName, output)
	if err == nil {
		t.Fatal("enrollment with a malformed JWT must fail")
	}
	wantStage := "enrollcng: validate OTT token"
	if runtime.GOOS != "windows" {
		wantStage = "enrollcng: CNG enrollment requires Windows"
	}
	if !strings.Contains(err.Error(), wantStage) {
		t.Fatalf("expected failure from the enrollment stage %q, got: %v", wantStage, err)
	}
	if strings.Contains(err.Error(), "TOKEN_SECRET") {
		t.Fatalf("enrollment error discloses the token: %v", err)
	}
	if fake.closed != 1 {
		t.Fatalf("setup signer closed %d times, want 1", fake.closed)
	}
	assertOutputRemoved(t, output)
}

func TestRunSetupSignerCloseFailureIsSafe(t *testing.T) {
	fake := newFakeSigner(t)
	fake.closeErr = errors.New("NCryptFreeObject hr=0x80090026 Keppin.Secret.Key")
	stubLoadOrCreate(t, func(string) (windowscng.Signer, error) { return fake, nil })
	jwtPath, output := runFixture(t)

	err := run(jwtPath, runKeyName, output)
	if err == nil || !strings.Contains(err.Error(), "close setup signer") {
		t.Fatalf("expected safe close-setup-signer error, got %v", err)
	}
	assertNoSensitive(t, err)
	assertOutputRemoved(t, output)
}
