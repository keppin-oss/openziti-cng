// Package keyref defines the shared, deliberately restricted CNG reference
// grammar.
//
// A reference names an existing machine-scoped CNG container and the access
// policy its DACL must hold. Exactly three canonical forms exist:
//
//	cng:<name>?policy=service-signer
//	cng:<name>?policy=privileged-only
//	cng:<name>?policy=service&service=<service-name>
//
// There is no default policy: a reference without one, including the legacy
// cng:<name>? form, is rejected. The persisted form carries the service name,
// never its SID.
package keyref

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/keppin-oss/cng/windowscng"
)

// ValidateName accepts ASCII letters/digits followed by letters/digits, dot,
// underscore or hyphen, up to 128 bytes. It never normalizes a name.
func ValidateName(name string) error {
	if len(name) == 0 || len(name) > 128 {
		return errors.New("CNG name must contain 1 to 128 ASCII characters")
	}
	for i, c := range []byte(name) {
		alphaNum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alphaNum && (i == 0 || c != '.' && c != '_' && c != '-') {
			return errors.New("CNG name must start with an ASCII letter or digit and contain only letters, digits, dot, underscore or hyphen")
		}
	}
	return nil
}

// Policy names, as they appear in the policy parameter of a reference.
const (
	PolicyServiceSigner  = "service-signer"
	PolicyPrivilegedOnly = "privileged-only"
	PolicyService        = "service"
)

type policyKind uint8

const (
	kindServiceSigner policyKind = iota + 1
	kindPrivilegedOnly
	kindService
)

// Policy is the persistable descriptor of a CNG key policy. It is distinct
// from the windowscng.KeyPolicy it resolves to: it holds only what the
// reference persists (the policy name and, for a service policy, the service
// name). The zero value is not a valid policy.
type Policy struct {
	kind    policyKind
	service string
}

// NewPolicy builds a descriptor from a policy name and, for PolicyService
// only, a service name. A service name with any other policy, an unknown
// policy, and a service name that windowscng.NewServicePolicy rejects are
// errors.
func NewPolicy(name, service string) (Policy, error) {
	switch name {
	case PolicyServiceSigner, PolicyPrivilegedOnly:
		if service != "" {
			return Policy{}, fmt.Errorf("CNG policy %q takes no service name", name)
		}
		if name == PolicyServiceSigner {
			return Policy{kind: kindServiceSigner}, nil
		}
		return Policy{kind: kindPrivilegedOnly}, nil
	case PolicyService:
		if _, err := windowscng.NewServicePolicy(service); err != nil {
			return Policy{}, errors.New("CNG service policy requires a valid service name (1 to 256 characters: ASCII letters, digits, dot, underscore or hyphen)")
		}
		return Policy{kind: kindService, service: service}, nil
	case "":
		return Policy{}, errors.New("CNG policy is required")
	default:
		return Policy{}, errors.New("unknown CNG policy")
	}
}

// KeyPolicyFromNames resolves a policy name and, for PolicyService only, a
// service name (as given on a command line) to the windowscng policy. It
// applies the same rules as NewPolicy: there is no default.
func KeyPolicyFromNames(name, service string) (windowscng.KeyPolicy, error) {
	p, err := NewPolicy(name, service)
	if err != nil {
		return nil, err
	}
	return p.KeyPolicy()
}

// FromKeyPolicy returns the descriptor of a windowscng policy value. It
// accepts PolicyServiceSigner, PolicyPrivilegedOnly and a ServicePolicy built
// by windowscng.NewServicePolicy, and rejects anything else.
func FromKeyPolicy(p windowscng.KeyPolicy) (Policy, error) {
	switch v := p.(type) {
	case windowscng.Policy:
		switch v {
		case windowscng.PolicyServiceSigner:
			return Policy{kind: kindServiceSigner}, nil
		case windowscng.PolicyPrivilegedOnly:
			return Policy{kind: kindPrivilegedOnly}, nil
		}
	case windowscng.ServicePolicy:
		resolved, err := windowscng.NewServicePolicy(v.ServiceName())
		if err == nil && resolved == v {
			return Policy{kind: kindService, service: v.ServiceName()}, nil
		}
	}
	return Policy{}, errors.New("unsupported CNG key policy")
}

// KeyPolicy resolves the descriptor to the windowscng policy passed to Open
// and Create.
func (p Policy) KeyPolicy() (windowscng.KeyPolicy, error) {
	switch p.kind {
	case kindServiceSigner:
		return windowscng.PolicyServiceSigner, nil
	case kindPrivilegedOnly:
		return windowscng.PolicyPrivilegedOnly, nil
	case kindService:
		sp, err := windowscng.NewServicePolicy(p.service)
		if err != nil {
			return nil, errors.New("invalid CNG service policy")
		}
		return sp, nil
	default:
		return nil, errors.New("invalid CNG policy")
	}
}

// query returns the canonical query of the descriptor. The service name needs
// no escaping: NewPolicy only accepts characters that are unreserved in a URL
// query.
func (p Policy) query() (string, error) {
	switch p.kind {
	case kindServiceSigner:
		return "policy=" + PolicyServiceSigner, nil
	case kindPrivilegedOnly:
		return "policy=" + PolicyPrivilegedOnly, nil
	case kindService:
		if _, err := NewPolicy(PolicyService, p.service); err != nil {
			return "", err
		}
		return "policy=" + PolicyService + "&service=" + p.service, nil
	default:
		return "", errors.New("invalid CNG policy")
	}
}

// Reference is a parsed CNG key reference.
type Reference struct {
	Name   string
	Policy Policy
}

// Format returns the canonical reference for a container name and policy.
func Format(name string, p Policy) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	q, err := p.query()
	if err != nil {
		return "", err
	}
	return "cng:" + name + "?" + q, nil
}

// errCanonical rejects any reference string that is not in canonical form.
var errCanonical = errors.New("expected canonical CNG reference cng:<name>?policy=<service-signer|privileged-only|service&service=<service-name>>")

// Parse accepts only the exact canonical form, as written by Format. It
// validates the original string, before OpenZiti's address parser runs, so it
// is also the check that rejects the cng://<name> alias that the parser
// normalizes away.
func Parse(ref string) (Reference, error) {
	rest, ok := strings.CutPrefix(ref, "cng:")
	if !ok {
		return Reference{}, errCanonical
	}
	name, query, ok := strings.Cut(rest, "?")
	if !ok {
		return Reference{}, errCanonical
	}
	if err := ValidateName(name); err != nil {
		return Reference{}, err
	}
	p, err := parseQuery(query)
	if err != nil {
		return Reference{}, err
	}
	// The byte-for-byte round trip rules out every other spelling.
	if canonical, err := Format(name, p); err != nil || canonical != ref {
		return Reference{}, errCanonical
	}
	return Reference{Name: name, Policy: p}, nil
}

// FromURL accepts the two shapes in which OpenZiti identity v1.0.140 hands a
// reference to the engine: on Windows parseAddr sets Host and RawQuery; on
// other platforms net/url sets Opaque and RawQuery. Both carry the same
// canonical query.
//
// The URL no longer shows whether the original string was cng:<name> or
// cng://<name>: both can reach the engine in the Host shape. Parse, which sees
// the original string, is the check that rejects the alias.
func FromURL(u *url.URL) (Reference, error) {
	if u == nil || u.Scheme != "cng" || u.User != nil || u.ForceQuery ||
		u.Fragment != "" || u.RawFragment != "" || u.Path != "" || u.RawPath != "" {
		return Reference{}, errors.New("invalid CNG reference")
	}
	name := u.Host
	if u.Opaque != "" {
		if name != "" {
			return Reference{}, errors.New("ambiguous CNG reference")
		}
		name = u.Opaque
	}
	if err := ValidateName(name); err != nil {
		return Reference{}, err
	}
	p, err := parseQuery(u.RawQuery)
	if err != nil {
		return Reference{}, err
	}
	return Reference{Name: name, Policy: p}, nil
}

// parseQuery accepts exactly one of the three canonical queries: parameters
// in fixed order, each once, no other parameter, no escaping.
func parseQuery(q string) (Policy, error) {
	if q == "" {
		return Policy{}, errors.New("CNG reference has no policy")
	}
	params := strings.Split(q, "&")
	first, ok := strings.CutPrefix(params[0], "policy=")
	if !ok {
		return Policy{}, errCanonical
	}
	var p Policy
	var err error
	switch len(params) {
	case 1:
		if first == PolicyService {
			return Policy{}, errors.New("CNG service policy requires a service parameter")
		}
		p, err = NewPolicy(first, "")
	case 2:
		service, ok := strings.CutPrefix(params[1], "service=")
		if !ok || first != PolicyService {
			return Policy{}, errCanonical
		}
		p, err = NewPolicy(PolicyService, service)
	default:
		return Policy{}, errCanonical
	}
	if err != nil {
		return Policy{}, err
	}
	if canonical, err := p.query(); err != nil || canonical != q {
		return Policy{}, errCanonical
	}
	return p, nil
}
