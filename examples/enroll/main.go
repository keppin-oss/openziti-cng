// Command enroll creates a new CNG key under an explicit policy, enrolls it
// with OpenZiti and saves a usable identity configuration. It never opens or
// adopts an existing key: a name already in use is refused. The JWT input file
// and output directory must be protected by the operator's Windows ACLs. No
// CNG private-key bytes are serialized.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/keppin-oss/cng/windowscng"
	_ "github.com/keppin-oss/openziti-cng/cngengine"
	"github.com/keppin-oss/openziti-cng/enrollcng"
	"github.com/keppin-oss/openziti-cng/internal/diagnostic"
	"github.com/keppin-oss/openziti-cng/internal/keyref"
	"github.com/openziti/sdk-golang/v2/ziti"
)

// reserveOutput refuses overwrites and checks the destination before enrollment.
// Mode 0600 is not a Windows DACL guarantee; use an appropriately protected folder.
func reserveOutput(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, diagnostic.Safe("reserve new configuration output", err)
	}
	return f, nil
}

func writeConfig(f *os.File, cfg *ziti.Config, ref string) error {
	if cfg == nil || cfg.ID.Key != ref || cfg.ID.Cert == "" {
		return errors.New("enrollment did not return the expected CNG identity configuration")
	}
	if err := json.NewEncoder(f).Encode(cfg); err != nil {
		return diagnostic.Safe("write configuration", err)
	}
	if err := f.Sync(); err != nil {
		return diagnostic.Safe("sync configuration", err)
	}
	return nil
}

// errKeyMayPersist is the operator-facing error for a Create failure in which
// windowscng could not delete the key it had just created. It is a fixed
// message: it never carries the native error, key name, token or paths.
var errKeyMayPersist = errors.New("create CNG key: a step after creating the new key failed (for example finalization, the policy check or public-key export) and the newly created key could not be removed; it may still be persisted, verify it and perform a controlled manual cleanup before retrying (sensitive details withheld)")

// errKeyExists is the operator-facing error for a Create refused because a key
// is already persisted under the name. The existing key is never opened,
// adopted or modified: enrolling an existing key is not this command's job.
var errKeyExists = errors.New("create CNG key: a key with this name already exists and was not opened, adopted or modified; choose a new name, or verify the existing key and remove it through a controlled lifecycle operation before retrying (sensitive details withheld)")

// errKeyPersisted is joined to every failure that follows a successful Create.
// It is a neutral statement of fact: this command never deletes the key it
// created, so a retry with the same name stops with errKeyExists and does not
// resume. It deliberately gives no removal advice, because the OTT may already
// have been consumed and the key may be needed to recover the identity.
var errKeyPersisted = errors.New("the CNG key created by this run remains persisted (this command never deletes it); a retry with the same name stops because the key already exists and does not resume")

// errEnrolledPreserve is joined to every failure that follows a successful
// enrollment: the OTT is consumed, the identity exists on the Controller and is
// bound to the persisted key, and the output may hold its configuration.
var errEnrolledPreserve = errors.New("enrollment completed and the OTT was consumed: preserve the CNG key and the configuration output, do not repeat the enrollment, and recover or verify the configuration before any further step")

// postCreateError joins the operator signals that apply to a failure, given how
// far run got: a key was created, and the OTT was consumed. Without a failure
// it adds nothing.
func postCreateError(err error, created, enrolled bool) error {
	if err == nil {
		return nil
	}
	if enrolled {
		err = errors.Join(err, errEnrolledPreserve)
	}
	if created {
		err = errors.Join(err, errKeyPersisted)
	}
	return err
}

// createError maps a windowscng.Create failure to a safe error.
// windowscng.ErrCleanupFailed and windowscng.ErrKeyExists get specific
// messages because the operator must act on a persisted key; every other
// failure stays generic. isCleanupFailed and isKeyExists are the platform
// adapter (create_windows.go / create_other.go): the sentinels are declared on
// every platform, but only Windows can return them. A possible residue is
// checked first: it is the outcome the operator must not miss.
func createError(err error) error {
	switch {
	case isCleanupFailed(err):
		return errKeyMayPersist
	case isKeyExists(err):
		return errKeyExists
	default:
		return diagnostic.Safe("create CNG key", err)
	}
}

// certMatchError redacts a CertMatchesSigner failure at this command's
// boundary, before it can reach log.Fatal. The helper keeps its public
// contract (its open failure wraps the windowscng error, key name and HRESULT
// included, so callers can test errors.Is(err, windowscng.ErrKeyNotFound)),
// but this command must not print those details.
func certMatchError(err error) error {
	return diagnostic.Safe("enrollment succeeded and configuration saved; verify saved certificate against CNG key", err)
}

// The following package variables are windowscng.Create, enrollcng.Enroll,
// enrollcng.CertMatchesSigner and (*os.File).Close. They are variables only so
// tests can inject failures and fakes without creating, opening or deleting a
// real CNG key or reaching a Controller; production code never reassigns them.
var (
	createSigner   = windowscng.Create
	enrollIdentity = enrollcng.Enroll
	certMatches    = enrollcng.CertMatchesSigner
	closeOutput    = (*os.File).Close
)

// run creates a new CNG key under policy, enrolls it and saves the identity
// configuration. It never opens or adopts an existing key: creating is a
// separate, create-only step (windowscng.Create), and the caller must
// serialize every lifecycle operation on the name across processes. The key
// is never deleted by this command. Every failure after Create carries
// errKeyPersisted, and every failure after the enrollment also carries
// errEnrolledPreserve (see postCreateError).
func run(jwtPath, keyName string, policy windowscng.KeyPolicy, output string) (resultErr error) {
	ref, err := enrollcng.KeyReference(keyName, policy)
	if err != nil {
		return err
	}
	created, enrolled := false, false
	// Registered first, so it runs last: it also covers a failure of the
	// deferred output close below.
	defer func() { resultErr = postCreateError(resultErr, created, enrolled) }()
	data, err := os.ReadFile(jwtPath)
	if err != nil {
		return diagnostic.Safe("read OTT JWT file", err)
	}
	jwt := strings.TrimSpace(string(data))
	if jwt == "" {
		return errors.New("OTT JWT file is empty")
	}
	f, err := reserveOutput(output)
	if err != nil {
		return err
	}
	defer func() {
		if err := closeOutput(f); err != nil {
			resultErr = errors.Join(resultErr, diagnostic.Safe("close configuration output", err))
		}
		// Only remove the file this call exclusively created, before a successful
		// enrollment. Preserve any output after consumption for operator recovery.
		if !enrolled {
			if err := os.Remove(output); err != nil {
				resultErr = errors.Join(resultErr, diagnostic.Safe("remove unused configuration output", err))
			}
		}
	}()
	signer, err := createSigner(keyName, policy)
	if err != nil {
		return createError(err)
	}
	created = true
	if err := signer.Close(); err != nil {
		return diagnostic.Safe("close setup signer", err)
	}
	cfg, err := enrollIdentity(jwt, keyName, policy)
	if err != nil {
		return err
	}
	enrolled = true
	if err := writeConfig(f, cfg, ref); err != nil {
		return errors.Join(errors.New("enrollment succeeded; output incomplete"), err)
	}
	ok, err := certMatches(cfg, keyName, policy)
	if err != nil {
		return certMatchError(err)
	}
	if !ok {
		return errors.New("saved certificate does not match the CNG signer")
	}
	return nil
}

func main() {
	jwtPath := flag.String("jwt", "", "path to a protected OTT JWT file (raw JWT arguments are not accepted)")
	keyName := flag.String("key", "Keppin.Demo.OpenZiti.CNG.v1", "name of the new CNG container (must not exist yet)")
	policyName := flag.String("policy", "", "key policy (required): service-signer, privileged-only or service")
	service := flag.String("service", "", "Windows service name, with -policy service only")
	output := flag.String("out", "", "new identity JSON file in a protected directory (required; never overwritten)")
	flag.Parse()
	if *jwtPath == "" || *output == "" || *policyName == "" {
		log.Fatal("-jwt, -policy and -out are required")
	}
	policy, err := keyref.KeyPolicyFromNames(*policyName, *service)
	if err != nil {
		log.Fatal(err)
	}
	if err := run(*jwtPath, *keyName, policy, *output); err != nil {
		log.Fatal(err)
	}
	fmt.Println("enrolled CNG identity configuration saved and public key matched")
}
