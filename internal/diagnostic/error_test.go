package diagnostic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
)

const (
	wantOperation = "operation failed"
	wantNetwork   = "network failure"
	wantTimeout   = "network timeout"
)

// multiErr stands in for a wrapper with several causes, such as the errors CNG
// builds with more than one %w.
type multiErr []error

func (m multiErr) Error() string   { return "multi" }
func (m multiErr) Unwrap() []error { return m }

// fixedWrap wraps an error with a fixed text: unlike fmt.Errorf, it never
// calls Error on its cause, which matters for self-referencing causes.
type fixedWrap struct{ cause error }

func (f fixedWrap) Error() string { return "wrap" }
func (f fixedWrap) Unwrap() error { return f.cause }

// loopErr is a pathological error whose Unwrap returns itself.
type loopErr struct{}

func (l *loopErr) Error() string { return "loop" }
func (l *loopErr) Unwrap() error { return l }

// The helpers build every case in memory: no socket, DNS, KSP or Controller.
var (
	localErrno    = syscall.ECONNREFUSED
	localDeadline = os.ErrDeadlineExceeded
)

func netRefused() error {
	return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
}

func netTimeout() error {
	return &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}
}

func dnsNotFound() error {
	return &net.DNSError{Err: "no such host", Name: "controller", IsNotFound: true}
}

func dnsTimeout() error {
	return &net.DNSError{Err: "i/o timeout", Name: "controller", IsTimeout: true}
}

func TestSafeCategory(t *testing.T) {
	parseErr := &url.Error{Op: "parse", URL: "https://controller/enroll?token=SECRET", Err: errors.New("invalid URL escape")}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"plain", errors.New("boom"), wantOperation},
		{"bare errno", localErrno, wantOperation},
		{"errno wrapped with %w", fmt.Errorf("read persisted DACL: %w", localErrno), wantOperation},
		{"errno 5 wrapped with %w", fmt.Errorf("read persisted DACL: %w", syscall.Errno(5)), wantOperation},
		{"errno in a CNG-like multi-cause wrapper", multiErr{errors.New("op failed"), localErrno}, wantOperation},
		{"errno in errors.Join", errors.Join(errors.New("op failed"), localErrno), wantOperation},
		{"bare local deadline", localDeadline, wantOperation},
		{"context deadline", context.DeadlineExceeded, wantOperation},
		{"local deadline in path error", &os.PathError{Op: "read", Path: "key", Err: localDeadline}, wantOperation},
		{"local deadline wrapped", fmt.Errorf("sign: %w", localDeadline), wantOperation},
		{"url parse error", parseErr, wantOperation},
		{"url error with local deadline", &url.Error{Op: "Post", URL: "https://controller/enroll", Err: localDeadline}, wantOperation},
		{"local deadline and local errno", errors.Join(localDeadline, localErrno), wantOperation},

		{"net op error with errno", netRefused(), wantNetwork},
		{"net op error wrapped", fmt.Errorf("enroll: %w", netRefused()), wantNetwork},
		{"dns error", dnsNotFound(), wantNetwork},
		{"url error around a net op error", &url.Error{Op: "Post", URL: "https://controller/enroll", Err: netRefused()}, wantNetwork},

		{"net timeout", netTimeout(), wantTimeout},
		{"net timeout wrapped", fmt.Errorf("enroll: %w", netTimeout()), wantTimeout},
		{"dns timeout", dnsTimeout(), wantTimeout},
		{"url error around a net timeout", &url.Error{Op: "Post", URL: "https://controller/enroll", Err: netTimeout()}, wantTimeout},

		{"errno then net error", errors.Join(localErrno, netRefused()), wantNetwork},
		{"net error then errno", errors.Join(netRefused(), localErrno), wantNetwork},
		{"local deadline then net error", errors.Join(localDeadline, netRefused()), wantNetwork},
		{"net error then local deadline", errors.Join(netRefused(), localDeadline), wantNetwork},
		{"generic then net timeout", errors.Join(errors.New("boom"), netTimeout()), wantTimeout},
		{"net timeout then generic", errors.Join(netTimeout(), errors.New("boom")), wantTimeout},
		{"net error then net timeout", errors.Join(netRefused(), netTimeout()), wantTimeout},
		{"net timeout then net error", errors.Join(netTimeout(), dnsNotFound()), wantTimeout},
		{"two net errors of the same type, timeout first", errors.Join(netTimeout(), netRefused()), wantTimeout},
		{"nested join, net timeout deep", errors.Join(errors.New("a"), errors.Join(localErrno, errors.Join(localDeadline, netTimeout()))), wantTimeout},
		{"nested join, net error deep", multiErr{errors.New("a"), fmt.Errorf("b: %w", multiErr{localErrno, dnsNotFound()})}, wantNetwork},
		{"local deadline does not become a net timeout", errors.Join(localDeadline, netRefused(), localErrno), wantNetwork},

		{"self-referencing error terminates", &loopErr{}, wantOperation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Safe("enroll", tc.err)
			want := "enroll: " + tc.want + " (sensitive details withheld)"
			if got == nil || got.Error() != want {
				t.Fatalf("Safe = %v, want %q", got, want)
			}
		})
	}
}

func TestSafeNilStaysNil(t *testing.T) {
	if Safe("enroll", nil) != nil {
		t.Fatal("nil should remain nil")
	}
}

func TestSafeErrorDoesNotRetainSecrets(t *testing.T) {
	secret := func(msg string) error { return errors.New(msg) }
	for _, cause := range []error{
		&url.Error{Op: "Post", URL: "https://controller/enroll?token=SECRET", Err: secret("RESPONSE_PRIVATE")},
		fmt.Errorf("JWT_PRIVATE: %w", secret("-----BEGIN PRIVATE KEY-----")),
		&url.Error{Op: "Post", URL: "https://controller/enroll?token=SECRET", Err: os.ErrDeadlineExceeded},
		&net.OpError{Op: "dial", Net: "tcp", Err: secret("RESPONSE_PRIVATE")},
		&net.OpError{Op: "read", Net: "tcp", Err: fmt.Errorf("JWT_PRIVATE: %w", os.ErrDeadlineExceeded)},
		&net.DNSError{Err: "RESPONSE_PRIVATE", Name: "controller.SECRET.example", IsTimeout: true},
		errors.Join(secret("JWT_PRIVATE"), &net.OpError{Op: "dial", Err: secret("RESPONSE_PRIVATE")}),
		multiErr{secret("RESPONSE_PRIVATE"), syscall.ECONNREFUSED},
	} {
		err := Safe("enroll", cause)
		if err == nil {
			t.Fatal("non-nil cause produced a nil error")
		}
		for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
			rendered := fmt.Sprintf(format, err)
			for _, secret := range []string{"SECRET", "PRIVATE", "https://", "controller"} {
				if strings.Contains(rendered, secret) {
					t.Fatalf("%q retained in safe error (%s): %s", secret, format, rendered)
				}
			}
		}
		if errors.Unwrap(err) != nil {
			t.Fatal("raw error remains reachable")
		}
		var opErr *net.OpError
		var dnsErr *net.DNSError
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, syscall.ECONNREFUSED) ||
			errors.As(err, &opErr) || errors.As(err, &dnsErr) {
			t.Fatal("cause remains reachable with errors.Is/errors.As")
		}
		if u, ok := err.(interface{ Unwrap() []error }); ok && u.Unwrap() != nil {
			t.Fatal("multiple causes remain reachable")
		}
	}
}

// localLeaves returns n distinct local errors, each one visit for the walker.
func localLeaves(n int) []error {
	leaves := make([]error, n)
	for i := range leaves {
		leaves[i] = errors.New("local")
	}
	return leaves
}

// visits of netTimeout(): the *net.OpError and its cause.
const netTimeoutVisits = 2

// wideTree returns a multi-cause error with the given number of local leaves
// and one net timeout at position pos (first, middle or last).
func wideTree(locals int, pos string) error {
	leaves := localLeaves(locals)
	var children []error
	switch pos {
	case "first":
		children = append([]error{netTimeout()}, leaves...)
	case "middle":
		children = append(append(append([]error{}, leaves[:locals/2]...), netTimeout()), leaves[locals/2:]...)
	default:
		children = append(leaves, netTimeout())
	}
	return multiErr(children)
}

// chain returns a chain of depth single-cause wrappers around cause.
func chain(depth int, cause error) error {
	err := cause
	for i := 0; i < depth; i++ {
		err = fmt.Errorf("wrap: %w", err)
	}
	return err
}

func TestSafeVisitLimitIsAContractNotAnOrderEffect(t *testing.T) {
	// The root counts one visit, the net timeout netTimeoutVisits.
	fits := maxNodes - 1 - netTimeoutVisits
	for _, pos := range []string{"first", "middle", "last"} {
		t.Run("fits the limit exactly, timeout "+pos, func(t *testing.T) {
			got := Safe("enroll", wideTree(fits, pos)).Error()
			if want := "enroll: " + wantTimeout + " (sensitive details withheld)"; got != want {
				t.Fatalf("Safe = %q, want %q", got, want)
			}
		})
		t.Run("one visit over the limit, timeout "+pos, func(t *testing.T) {
			// A tree over the limit is not classified, wherever the evidence is.
			got := Safe("enroll", wideTree(fits+1, pos)).Error()
			if want := "enroll: " + wantOperation + " (sensitive details withheld)"; got != want {
				t.Fatalf("Safe = %q, want %q", got, want)
			}
		})
	}

	// A chain of single-cause wrappers: depth wrappers, the net timeout and its
	// cause are depth+netTimeoutVisits visits.
	chainFits := maxNodes - netTimeoutVisits
	if got := Safe("enroll", chain(chainFits, netTimeout())).Error(); got != "enroll: "+wantTimeout+" (sensitive details withheld)" {
		t.Fatalf("chain that fits: %q", got)
	}
	if got := Safe("enroll", chain(chainFits+1, netTimeout())).Error(); got != "enroll: "+wantOperation+" (sensitive details withheld)" {
		t.Fatalf("chain over the limit: %q", got)
	}

	// A deep local branch before and after a net timeout: same result.
	deep := chain(maxNodes, errors.New("local"))
	for name, err := range map[string]error{
		"deep branch first": errors.Join(deep, netTimeout()),
		"deep branch last":  errors.Join(netTimeout(), deep),
	} {
		if got := Safe("enroll", err).Error(); got != "enroll: "+wantOperation+" (sensitive details withheld)" {
			t.Fatalf("%s: %q", name, got)
		}
	}
}

func TestSafeCountsASharedCauseOncePerPath(t *testing.T) {
	// Each level joins the previous one with itself: few distinct errors, but
	// 2^depth paths.
	diamond := func(depth int) error {
		err := netTimeout()
		for i := 0; i < depth; i++ {
			err = errors.Join(err, err)
		}
		return err
	}
	if got := Safe("enroll", diamond(3)).Error(); got != "enroll: "+wantTimeout+" (sensitive details withheld)" {
		t.Fatalf("small diamond: %q", got)
	}
	if got := Safe("enroll", diamond(12)).Error(); got != "enroll: "+wantOperation+" (sensitive details withheld)" {
		t.Fatalf("large diamond (4096 paths, 13 distinct errors): %q", got)
	}
}

// A tree far over the limit is not classified, wherever the net timeout is.
// The early exit of the loop over the children changes the cost of the walk,
// not its result, so this test cannot observe it; it only checks the result.
func TestSafeTreeFarOverTheLimitIsNotClassified(t *testing.T) {
	for _, pos := range []string{"first", "middle", "last"} {
		t.Run("timeout "+pos, func(t *testing.T) {
			got := Safe("enroll", wideTree(10*maxNodes, pos)).Error()
			if want := "enroll: " + wantOperation + " (sensitive details withheld)"; got != want {
				t.Fatalf("Safe = %q, want %q", got, want)
			}
		})
	}
}

// TestSafeNilCausesDoNotCountAsVisits pads a list of causes with nil errors,
// which Unwrap may return and which must neither consume the budget nor set
// truncated.
func TestSafeNilCausesDoNotCountAsVisits(t *testing.T) {
	// The root counts one visit and the net timeout netTimeoutVisits.
	fits := maxNodes - 1 - netTimeoutVisits
	build := func(leaves int, trailingNils int) error {
		children := make([]error, 0, 2*leaves+trailingNils+2)
		children = append(children, nil)
		for i := 0; i < leaves; i++ {
			children = append(children, errors.New("local"), nil)
		}
		children = append(children, netTimeout())
		for i := 0; i < trailingNils; i++ {
			children = append(children, nil)
		}
		return multiErr(children)
	}
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"exactly the limit, nils interleaved and trailing": {build(fits, 5), wantTimeout},
		"one visit over the limit, nils interleaved":       {build(fits+1, 5), wantOperation},
		"single-cause wrapper around nil is a leaf":        {fixedWrap{nil}, wantOperation},
		"net timeout after a wrapper around nil":           {multiErr{fixedWrap{nil}, netTimeout()}, wantTimeout},
	} {
		if got, want := Safe("enroll", tc.err).Error(), "enroll: "+tc.want+" (sensitive details withheld)"; got != want {
			t.Fatalf("%s: Safe = %q, want %q", name, got, want)
		}
	}
}

func TestSafeSelfReferencingNetErrorsTerminate(t *testing.T) {
	// (*net.OpError).Timeout would recurse without bound on these.
	self := &net.OpError{Op: "read", Net: "tcp"}
	self.Err = self
	a := &net.OpError{Op: "read", Net: "tcp"}
	b := &net.OpError{Op: "write", Net: "tcp"}
	a.Err, b.Err = b, a
	for name, err := range map[string]error{
		"op error that wraps itself":   self,
		"two op errors that wrap each": a,
		"wrapped self-reference":       fixedWrap{self},
	} {
		if got := Safe("sign", err).Error(); got != "sign: "+wantOperation+" (sensitive details withheld)" {
			t.Fatalf("%s: %q", name, got)
		}
	}
}

func TestSafeOpErrorTimeoutComesFromItsOwnCause(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"cause reports a timeout", &net.OpError{Op: "read", Err: os.ErrDeadlineExceeded}, wantTimeout},
		{"cause behind one syscall error reports a timeout", &net.OpError{Op: "read", Err: os.NewSyscallError("read", os.ErrDeadlineExceeded)}, wantTimeout},
		{"cause is a DNS timeout", &net.OpError{Op: "dial", Err: dnsTimeout()}, wantTimeout},
		{"cause is a net timeout", &net.OpError{Op: "dial", Err: netTimeout()}, wantTimeout},
		// net.OpError.Timeout does not look through %w, and neither does Safe.
		{"deadline behind a wrapper stays a network failure", &net.OpError{Op: "read", Err: fmt.Errorf("wrapped: %w", os.ErrDeadlineExceeded)}, wantNetwork},
		{"net timeout behind a wrapper is found", fmt.Errorf("wrapped: %w", netTimeout()), wantTimeout},
		{"cause without a timeout method", &net.OpError{Op: "read", Err: errors.New("boom")}, wantNetwork},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := Safe("enroll", tc.err).Error(), "enroll: "+tc.want+" (sensitive details withheld)"; got != want {
				t.Fatalf("Safe = %q, want %q", got, want)
			}
		})
	}
}
