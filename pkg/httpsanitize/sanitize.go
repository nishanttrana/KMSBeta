// Package httpsanitize provides helpers to sanitize values before using them
// in HTTP headers or log messages, preventing header injection and log
// injection attacks.
package httpsanitize

import "strings"

// HeaderValue strips CR, LF, and null bytes from a string before it is used
// as an HTTP header value. This prevents HTTP response splitting / header
// injection (CWE-113).
func HeaderValue(v string) string {
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", "")
	v = strings.ReplaceAll(v, "\x00", "")
	return v
}

// LogValue strips CR, LF, and null bytes and replaces them with a safe
// placeholder to prevent log injection / log forgery attacks.
func LogValue(v string) string {
	v = strings.ReplaceAll(v, "\r", "\\r")
	v = strings.ReplaceAll(v, "\n", "\\n")
	v = strings.ReplaceAll(v, "\x00", "\\0")
	return v
}

// ContentDispositionFilename sanitizes a filename for use in a
// Content-Disposition header, removing path separators and control characters.
func ContentDispositionFilename(name string) string {
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, "\"", "_")
	name = HeaderValue(name)
	return name
}
