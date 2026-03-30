package logsanitize

import "strings"

// Input removes newlines, carriage returns, tabs, and other control characters
// from user-provided input before it is written to log output. This prevents
// log injection attacks where an attacker crafts input containing newline
// sequences to forge log entries or corrupt structured logging.
func Input(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString("\\n")
		case r == '\r':
			b.WriteString("\\r")
		case r == '\t':
			b.WriteString("\\t")
		case r < 0x20 || r == 0x7f:
			// Replace all other ASCII control chars with a placeholder.
			b.WriteRune('\uFFFD')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
