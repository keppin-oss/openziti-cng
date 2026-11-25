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
	"github.com/keppin-oss/openziti-cng/enrollcng"
	"github.com/openziti/identity"
	"github.com/openziti/sdk-golang/v2/ziti"
)

// These tests replace createSigner with in-memory fakes. No CNG key is
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

// createCall records one call to the createSigner seam.
type createCall struct {
	name   string
	policy windowscng.KeyPolicy
}

func stubCreate(t *testing.T, fn func(string, windowscng.KeyPolicy) (windowscng.Signer, error)) *[]createCall {
	t.Helper()
	var calls []createCall
	orig := createSigner
	createSigner = func(name string, policy windowscng.KeyPolicy) (windowscng.Signer, error) {
		calls = append(calls, createCall{name, policy})
		return fn(name, policy)
	}
	t.Cleanup(func() { createSigner = orig })
	return &calls
}

const (
	runKeyName = "Keppin.Secret.Key"
	runPolicy  = windowscng.PolicyPrivilegedOnly
)

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

// TestRunCreateRollbackSucceededStaysGeneric uses the error shape of a newly
// created key that failed after creation and was deleted again (cleanup
// succeeded): the operator gets the generic safe error, and Create was called
// exactly once with the requested name and policy.
func TestRunCreateRollbackSucceededStaysGeneric(t *testing.T) {
	calls := stubCreate(t, func(string, windowscng.KeyPolicy) (windowscng.Signer, error) {
		return nil, fmt.Errorf("%w (the key created by this call was deleted)", syntheticNative())
	})
	jwtPath, output := runFixture(t)

	err := run(jwtPath, runKeyName, runPolicy, output)
	assertGenericError(t, err)
	assertOutputRemoved(t, output)
	if len(*calls) != 1 || (*calls)[0].name != runKeyName || (*calls)[0].policy != runPolicy {
		t.Fatalf("Create calls = %+v, want exactly [{%s %v}]", *calls, runKeyName, runPolicy)
	}
}

func TestRunInvalidKeyNameOrPolicyNeverCreates(t *testing.T) {
	calls := stubCreate(t, func(string, windowscng.KeyPolicy) (windowscng.Signer, error) {
		t.Fatal("Create reached for an invalid key name or policy")
		return nil, nil
	})
	for _, c := range []struct {
		name   string
		policy windowscng.KeyPolicy
	}{
		{"a?b", runPolicy},
		{runKeyName, nil},
		{runKeyName, windowscng.Policy(0)},
		{runKeyName, windowscng.ServicePolicy{}},
	} {
		jwtPath, output := runFixture(t)
		if err := run(jwtPath, c.name, c.policy, output); err == nil {
			t.Fatalf("run accepted name %q with policy %v", c.name, c.policy)
		}
		if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("output reserved for an invalid key name or policy")
		}
	}
	if len(*calls) != 0 {
		t.Fatal("Create called for an invalid key name or policy")
	}
}

// TestRunSetupSignerClosedOnceAndEnrollmentFailsSafely covers the ordinary
// path up to the network boundary: after a successful Create, run closes the
// setup signer exactly once and the failure comes from the enrollment stage
// (malformed JWT on Windows, platform check elsewhere) without disclosing the
// token. It uses the real enrollcng.Enroll. The error carries the neutral
// persisted-key signal and, since the enrollment did not complete, not the
// post-enrollment one.
func TestRunSetupSignerClosedOnceAndEnrollmentFailsSafely(t *testing.T) {
	fake := newFakeSigner(t)
	stubCreate(t, func(string, windowscng.KeyPolicy) (windowscng.Signer, error) { return fake, nil })
	jwtPath, output := runFixture(t)

	err := run(jwtPath, runKeyName, runPolicy, output)
	if err == nil {
		t.Fatal("enrollment with a malformed JWT must fail")
	}
	assertSignals(t, err, true, false)
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
	stubCreate(t, func(string, windowscng.KeyPolicy) (windowscng.Signer, error) { return fake, nil })
	jwtPath, output := runFixture(t)

	err := run(jwtPath, runKeyName, runPolicy, output)
	if err == nil || !strings.Contains(err.Error(), "close setup signer") {
		t.Fatalf("expected safe close-setup-signer error, got %v", err)
	}
	assertSignals(t, err, true, false)
	assertNoSensitive(t, err)
	assertOutputRemoved(t, output)
}

// assertSignals checks which operator signals an error of run carries.
func assertSignals(t *testing.T, err error, persisted, enrolled bool) {
	t.Helper()
	if got := errors.Is(err, errKeyPersisted); got != persisted {
		t.Fatalf("errKeyPersisted present = %v, want %v: %v", got, persisted, err)
	}
	if got := errors.Is(err, errEnrolledPreserve); got != enrolled {
		t.Fatalf("errEnrolledPreserve present = %v, want %v: %v", got, enrolled, err)
	}
}

// stubEnrollment replaces the enrollment and certificate check seams. enroll
// returns cfg (or err); match is the CertMatchesSigner result. No Controller is
// reached and no CNG key is opened.
func stubEnrollment(t *testing.T, cfg *ziti.Config, enrollErr error, match bool, matchErr error) {
	t.Helper()
	origEnroll, origMatch := enrollIdentity, certMatches
	enrollIdentity = func(string, string, windowscng.KeyPolicy) (*ziti.Config, error) { return cfg, enrollErr }
	certMatches = func(*ziti.Config, string, windowscng.KeyPolicy) (bool, error) { return match, matchErr }
	t.Cleanup(func() { enrollIdentity, certMatches = origEnroll, origMatch })
}

func stubCloseOutput(t *testing.T, err error) {
	t.Helper()
	orig := closeOutput
	closeOutput = func(f *os.File) error {
		if cerr := f.Close(); cerr != nil {
			return cerr
		}
		return err
	}
	t.Cleanup(func() { closeOutput = orig })
}

// enrolledConfig is an enrollment result for runKeyName under runPolicy.
func enrolledConfig(t *testing.T) *ziti.Config {
	t.Helper()
	ref, err := enrollcng.KeyReference(runKeyName, runPolicy)
	if err != nil {
		t.Fatal(err)
	}
	return &ziti.Config{ZtAPI: "https://controller", ID: identity.Config{Key: ref, Cert: "pem:CERT", CA: "pem:CA"}}
}

func assertOutputKept(t *testing.T, output string) {
	t.Helper()
	if _, err := os.Stat(output); err != nil {
		t.Fatalf("output must be preserved after the OTT was consumed: %v", err)
	}
}

func TestRunSuccessKeepsOutputAndCarriesNoSignal(t *testing.T) {
	stubCreate(t, func(string, windowscng.KeyPolicy) (windowscng.Signer, error) { return newFakeSigner(t), nil })
	stubEnrollment(t, enrolledConfig(t), nil, true, nil)
	jwtPath, output := runFixture(t)

	if err := run(jwtPath, runKeyName, runPolicy, output); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, err := ziti.NewConfigFromFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID.Key != enrolledConfig(t).ID.Key {
		t.Fatalf("saved key reference = %q", got.ID.Key)
	}
}

// TestRunCreateFailureCarriesNoSignal: no key was created by this run, so
// neither signal applies, even if closing the output also fails.
func TestRunCreateFailureCarriesNoSignal(t *testing.T) {
	stubCreate(t, func(string, windowscng.KeyPolicy) (windowscng.Signer, error) { return nil, syntheticNative() })
	stubCloseOutput(t, errors.New("synthetic close failure C:\\secret"))
	jwtPath, output := runFixture(t)

	err := run(jwtPath, runKeyName, runPolicy, output)
	if err == nil {
		t.Fatal("Create failure accepted")
	}
	assertSignals(t, err, false, false)
	assertNoSensitive(t, err)
}

// TestRunFailuresAfterEnrollmentPreserveKeyAndOutput covers every failure after
// the OTT was consumed: incomplete output, certificate check error, mismatch,
// and the deferred close of the output. Each carries both signals, keeps the
// output and gives no removal advice.
func TestRunFailuresAfterEnrollmentPreserveKeyAndOutput(t *testing.T) {
	wrongKey := enrolledConfig(t)
	wrongKey.ID.Key = "pem:SECRET"
	cases := []struct {
		name     string
		cfg      *ziti.Config
		match    bool
		matchErr error
		closeErr error
		stage    string
	}{
		{"incomplete output", wrongKey, true, nil, nil, "output incomplete"},
		{"certificate check error", enrolledConfig(t), false, fmt.Errorf("open CNG key %q: hr=0x80090016", runKeyName), nil, "verify saved certificate against CNG key"},
		{"certificate mismatch", enrolledConfig(t), false, nil, nil, "does not match the CNG signer"},
		{"deferred output close", enrolledConfig(t), true, nil, errors.New("synthetic close failure C:\\secret"), "close configuration output"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stubCreate(t, func(string, windowscng.KeyPolicy) (windowscng.Signer, error) { return newFakeSigner(t), nil })
			stubEnrollment(t, c.cfg, nil, c.match, c.matchErr)
			stubCloseOutput(t, c.closeErr)
			jwtPath, output := runFixture(t)

			err := run(jwtPath, runKeyName, runPolicy, output)
			if err == nil || !strings.Contains(err.Error(), c.stage) {
				t.Fatalf("expected a failure at %q, got %v", c.stage, err)
			}
			assertSignals(t, err, true, true)
			assertNoSensitive(t, err)
			if strings.Contains(strings.ToLower(err.Error()), "remove") {
				t.Fatalf("post-enrollment error must not advise removing anything: %v", err)
			}
			assertOutputKept(t, output)
		})
	}
}

// TestRunEnrollmentErrorCarriesOnlyThePersistedSignal: when Enroll itself
// fails, run cannot tell whether the OTT was consumed, so it states the key is
// persisted and gives no removal advice.
func TestRunEnrollmentErrorCarriesOnlyThePersistedSignal(t *testing.T) {
	stubCreate(t, func(string, windowscng.KeyPolicy) (windowscng.Signer, error) { return newFakeSigner(t), nil })
	stubEnrollment(t, nil, errors.New("enrollcng: enroll: network failure (sensitive details withheld)"), false, nil)
	jwtPath, output := runFixture(t)

	err := run(jwtPath, runKeyName, runPolicy, output)
	if err == nil {
		t.Fatal("enrollment failure accepted")
	}
	assertSignals(t, err, true, false)
	if strings.Contains(strings.ToLower(err.Error()), "remove") {
		t.Fatalf("error after Create must not advise removing the key: %v", err)
	}
	assertOutputRemoved(t, output)
}
