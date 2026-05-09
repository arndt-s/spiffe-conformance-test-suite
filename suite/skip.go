package suite

import (
	"errors"
	"fmt"
)

// skipError is the sentinel returned by Skip; the runner detects it via
// errors.As to map a test result to result.StatusSkip.
type skipError struct {
	msg string
}

func (e *skipError) Error() string { return e.msg }

// Skip returns an error that, when returned from a TestFunc, instructs
// the runner to mark the case as Skipped (rather than Failed) with the
// given formatted message. Use this for capability-gated tests that
// cannot run against the harness in front of them — for example, when
// the SDK harness does not advertise the required capability.
func Skip(format string, a ...any) error {
	return &skipError{msg: fmt.Sprintf(format, a...)}
}

// IsSkip reports whether err was produced by Skip and returns the
// underlying message. The runner uses this; tests typically just return
// the error verbatim.
func IsSkip(err error) (string, bool) {
	var s *skipError
	if errors.As(err, &s) {
		return s.msg, true
	}
	return "", false
}
