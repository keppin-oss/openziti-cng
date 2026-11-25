package keyref

import (
	"net/url"
	"strings"
	"testing"

	"github.com/keppin-oss/cng/windowscng"
)

func mustPolicy(t *testing.T, name, service string) Policy {
	t.Helper()
	p, err := NewPolicy(name, service)
	if err != nil {
		t.Fatalf("NewPolicy(%q, %q): %v", name, service, err)
	}
	return p
}

func mustServicePolicy(t *testing.T, service string) windowscng.ServicePolicy {
	t.Helper()
	sp, err := windowscng.NewServicePolicy(service)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

// canonicalCases lists one policy of each kind, its canonical query and the
// windowscng policy it resolves to.
func canonicalCases(t *testing.T) []struct {
	policy   Policy
	query    string
	resolved windowscng.KeyPolicy
} {
	return []struct {
		policy   Policy
		query    string
		resolved windowscng.KeyPolicy
	}{
		{mustPolicy(t, PolicyServiceSigner, ""), "policy=service-signer", windowscng.PolicyServiceSigner},
		{mustPolicy(t, PolicyPrivilegedOnly, ""), "policy=privileged-only", windowscng.PolicyPrivilegedOnly},
		{mustPolicy(t, PolicyService, "KeppinAgent"), "policy=service&service=KeppinAgent", mustServicePolicy(t, "KeppinAgent")},
		{mustPolicy(t, PolicyService, "a.b_c-1"), "policy=service&service=a.b_c-1", mustServicePolicy(t, "a.b_c-1")},
	}
}

// TestRoundTrip checks, for every policy kind and several names, that Format
// writes the canonical string, that Parse returns the same name and policy
// and that both URL shapes OpenZiti produces resolve to them too.
func TestRoundTrip(t *testing.T) {
	for _, c := range canonicalCases(t) {
		for _, name := range []string{"A", "Keppin.Test-001_key", strings.Repeat("a", 128)} {
			ref, err := Format(name, c.policy)
			if err != nil {
				t.Fatal(err)
			}
			if want := "cng:" + name + "?" + c.query; ref != want {
				t.Fatalf("Format = %q, want %q", ref, want)
			}
			got, err := Parse(ref)
			if err != nil || got.Name != name || got.Policy != c.policy {
				t.Fatalf("canonical round trip of %q failed: %+v %v", ref, got, err)
			}
			// Other platforms: net/url gives Opaque + RawQuery.
			u, err := url.Parse(ref)
			if err != nil {
				t.Fatal(err)
			}
			got, err = FromURL(u)
			if err != nil || got.Name != name || got.Policy != c.policy {
				t.Fatalf("net/url round trip of %q failed: %+v %v", ref, got, err)
			}
			// Windows: identity's parseAddr gives Host + RawQuery.
			got, err = FromURL(&url.URL{Scheme: "cng", Host: name, RawQuery: c.query})
			if err != nil || got.Name != name || got.Policy != c.policy {
				t.Fatalf("Windows round trip of %q failed: %+v %v", ref, got, err)
			}
			resolved, err := got.Policy.KeyPolicy()
			if err != nil || resolved != c.resolved {
				t.Fatalf("KeyPolicy of %q = %v %v, want %v", ref, resolved, err, c.resolved)
			}
		}
	}
}

func TestFromKeyPolicy(t *testing.T) {
	for _, c := range canonicalCases(t) {
		got, err := FromKeyPolicy(c.resolved)
		if err != nil || got != c.policy {
			t.Fatalf("FromKeyPolicy(%v) = %+v %v, want %+v", c.resolved, got, err, c.policy)
		}
	}
	for _, p := range []windowscng.KeyPolicy{nil, windowscng.Policy(0), windowscng.Policy(99), windowscng.ServicePolicy{}} {
		if _, err := FromKeyPolicy(p); err == nil {
			t.Errorf("FromKeyPolicy(%v) accepted an invalid policy", p)
		}
	}
}

func TestNewPolicyRejects(t *testing.T) {
	for _, c := range [][2]string{
		{"", ""},
		{"unknown", ""},
		{"Service-Signer", ""},
		{"service-signer", "KeppinAgent"},
		{"privileged-only", "KeppinAgent"},
		{"service", ""},
		{"service", "Keppin Agent"},
		{"service", "Keppin%20Agent"},
		{"service", "Keppin&Agent"},
		{"service", "Keppin=Agent"},
		{"service", "Kèppin"},
		{"service", strings.Repeat("a", 257)},
	} {
		if _, err := NewPolicy(c[0], c[1]); err == nil {
			t.Errorf("NewPolicy(%q, %q) accepted", c[0], c[1])
		}
	}
	if _, err := KeyPolicyFromNames("", ""); err == nil {
		t.Error("KeyPolicyFromNames without a policy accepted: there is no default")
	}
}

func TestZeroPolicyIsInvalid(t *testing.T) {
	if _, err := Format("name", Policy{}); err == nil {
		t.Fatal("Format accepted the zero policy")
	}
	if _, err := (Policy{}).KeyPolicy(); err == nil {
		t.Fatal("the zero policy resolved to a windowscng policy")
	}
}

func TestRejectAmbiguousNames(t *testing.T) {
	p := mustPolicy(t, PolicyServiceSigner, "")
	for _, name := range []string{"", " name", "name ", "a b", "//name", "/name", "a/b", "a\\b", "a:b", "a?b", "a#b", "a%b", "a@b", "a\x00b", "a\nb", "é", ".name", "-name", strings.Repeat("a", 129)} {
		if _, err := Format(name, p); err == nil {
			t.Errorf("accepted invalid name %q", name)
		}
	}
}

func TestRejectNoncanonicalReferences(t *testing.T) {
	for _, ref := range []string{
		// Not a CNG reference, or not canonical.
		"pem:PRIVATE", "file:key", "CNG:name?policy=service-signer", " cng:name?policy=service-signer",
		"cng:name?policy=service-signer ", "cng:name%20?policy=service-signer",
		// The cng:// alias, which OpenZiti's parser normalizes away.
		"cng://name?policy=service-signer",
		// No policy: the legacy forms and the empty query.
		"cng:name", "cng:name?", "cng:name??",
		// Unknown, duplicated, reordered or extra parameters.
		"cng:name?policy=", "cng:name?policy=unknown", "cng:name?policy=Service-Signer",
		"cng:name?token=SECRET", "cng:name?policy=service-signer&token=SECRET",
		"cng:name?policy=service-signer&policy=service-signer",
		"cng:name?policy=service-signer&policy=privileged-only",
		"cng:name?service=KeppinAgent&policy=service",
		"cng:name?policy=service-signer&service=KeppinAgent",
		"cng:name?policy=service", "cng:name?policy=service&service=",
		"cng:name?policy=service&service=KeppinAgent&service=KeppinAgent",
		"cng:name?policy=service&service=KeppinAgent&extra=1",
		// Escaped, separator or fragment variants.
		"cng:name?policy=service%2Dsigner", "cng:name?policy=service&service=Keppin%41gent",
		"cng:name?policy=service&service=Keppin+Agent", "cng:name?policy=service-signer;x=1",
		"cng:name?policy=service-signer#frag", "cng:name?#frag",
		"cng:name?&policy=service-signer", "cng:name?policy=service-signer&",
	} {
		if _, err := Parse(ref); err == nil {
			t.Errorf("accepted invalid reference %q", ref)
		}
	}
}

func TestRejectURLAmbiguities(t *testing.T) {
	q := "policy=service-signer"
	for _, u := range []*url.URL{
		nil,
		{Scheme: "file", Host: "name", RawQuery: q},
		{Scheme: "cng", Host: "name"},
		{Scheme: "cng", Opaque: "name"},
		{Scheme: "cng", Host: "name", ForceQuery: true},
		{Scheme: "cng", Host: "name", Opaque: "other", RawQuery: q},
		{Scheme: "cng", Host: "name", Path: "/other", RawQuery: q},
		{Scheme: "cng", Host: "name", RawQuery: "token=secret"},
		{Scheme: "cng", Host: "name", RawQuery: q + "&token=secret"},
		{Scheme: "cng", Host: "name", RawQuery: "policy=service"},
		{Scheme: "cng", Host: "name", RawQuery: q, User: url.User("user")},
		{Scheme: "cng", Host: "name", RawQuery: q, Fragment: "secret"},
		{Scheme: "cng", Opaque: "name?", RawQuery: q},
	} {
		if _, err := FromURL(u); err == nil {
			t.Errorf("accepted ambiguous URL %#v", u)
		}
	}
}
