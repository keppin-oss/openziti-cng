// Package diagnostic provides errors safe to print at identity boundaries.
package diagnostic

import (
	"fmt"
	"net"
	"os"
)

const (
	categoryOperation = "operation failed"
	categoryNetwork   = "network failure"
	categoryTimeout   = "network timeout"
)

// maxNodes bounds the number of errors visited by one Safe call. Every node
// reached through Unwrap counts once per path that reaches it, so a cause
// shared by several parents is counted several times.
const maxNodes = 1024

// Safe deliberately does not retain or wrap the original error: it may contain
// an enrollment token, identity material, a URL or a controller response body.
//
// The category is derived from positive evidence of a network error only: a
// *net.OpError or a *net.DNSError anywhere in the error tree. Satisfying the
// net.Error interface is not evidence (syscall.Errno, os.ErrDeadlineExceeded
// and a *url.Error that reports a local parsing failure all satisfy it), and
// neither the error text, the stage nor numeric system error codes are used.
// Without such evidence the category is "operation failed". When the tree holds
// several causes, the strongest category present wins, whatever the order of
// the branches: "network timeout" (a recognized network error that reports a
// timeout), then "network failure" (any recognized network error), then
// "operation failed". The result says that the category is present, not that
// every cause is of that kind.
//
// The tree is walked through Unwrap() error and Unwrap() []error. A tree with
// more than maxNodes visits is not classified: the category is then "operation
// failed", whatever evidence the part already visited held. The number of
// visits depends only on the tree, so this does not depend on the order of the
// branches either. The bound limits the classifier's own walk; the Unwrap and
// Timeout methods of the errors it calls are assumed to terminate. The
// classifier does not delegate the timeout of a *net.OpError or *net.DNSError
// to another recognized network error, which it visits as a node of its own.
// That protects a cause that is directly (or behind one *os.SyscallError) a
// *net.OpError or *net.DNSError; a cycle through another wrapper that delegates
// Timeout, such as a *url.Error or an *os.PathError, is outside the assumption
// above and can still exhaust the stack.
func Safe(stage string, err error) error {
	if err == nil {
		return nil
	}
	category := categoryOperation
	w := walker{budget: maxNodes}
	found := w.classify(err)
	if !w.truncated {
		switch found {
		case evidenceTimeout:
			category = categoryTimeout
		case evidenceNetwork:
			category = categoryNetwork
		}
	}
	return fmt.Errorf("%s: %s (sensitive details withheld)", stage, category)
}

type evidence int

// The order is the precedence: a larger value wins.
const (
	evidenceNone evidence = iota
	evidenceNetwork
	evidenceTimeout
)

// walker visits an error tree with a bounded number of visits. truncated
// reports that a non-nil error could not be visited.
type walker struct {
	budget    int
	truncated bool
}

// classify returns the strongest evidence found below err. Every node is
// examined independently, so the result does not depend on the order of the
// branches of an errors.Join.
func (w *walker) classify(err error) evidence {
	if err == nil {
		return evidenceNone
	}
	if w.budget <= 0 {
		w.truncated = true
		return evidenceNone
	}
	w.budget--

	found := evidenceNone
	switch e := err.(type) {
	case *net.OpError:
		found = networkEvidence(opErrorTimeout(e))
	case *net.DNSError:
		found = networkEvidence(e.IsTimeout)
	}

	switch u := err.(type) {
	case interface{ Unwrap() error }:
		found = max(found, w.classify(u.Unwrap()))
	case interface{ Unwrap() []error }:
		for _, cause := range u.Unwrap() {
			if cause == nil {
				continue
			}
			if w.budget <= 0 {
				w.truncated = true
				break
			}
			found = max(found, w.classify(cause))
		}
	}
	return found
}

// networkEvidence maps a recognized network error to its evidence level. The
// timeout belongs to that recognized error, never to an independent local
// branch of the tree.
func networkEvidence(timeout bool) evidence {
	if timeout {
		return evidenceTimeout
	}
	return evidenceNetwork
}

// opErrorTimeout reports whether e's own cause reports a timeout. It follows
// the rule of (*net.OpError).Timeout (one *os.SyscallError level, then the
// cause's Timeout method), except that it does not call Timeout on a cause that
// is itself a *net.OpError or *net.DNSError: such a cause is visited as a node
// of its own, and calling it here would make a self-referencing *net.OpError
// recurse without bound. It does not protect a cycle through other wrappers
// that delegate Timeout (see Safe).
func opErrorTimeout(e *net.OpError) bool {
	cause := e.Err
	if se, ok := cause.(*os.SyscallError); ok {
		cause = se.Err
	}
	switch cause.(type) {
	case *net.OpError, *net.DNSError:
		return false
	}
	t, ok := cause.(interface{ Timeout() bool })
	return ok && t.Timeout()
}
