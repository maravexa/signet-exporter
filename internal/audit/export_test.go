package audit

import "io"

// NewLoggerForTest creates an audit logger writing to w. Only available in tests.
func NewLoggerForTest(w io.Writer) *Logger {
	return newLoggerFromWriter(w)
}
