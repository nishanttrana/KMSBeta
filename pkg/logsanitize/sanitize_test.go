package logsanitize

import "testing"

func TestInput(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"clean", "hello world", "hello world"},
		{"newline", "line1\nline2", "line1\\nline2"},
		{"carriage_return", "line1\rline2", "line1\\rline2"},
		{"tab", "col1\tcol2", "col1\\tcol2"},
		{"crlf", "line1\r\nline2", "line1\\r\\nline2"},
		{"null_byte", "a\x00b", "a\uFFFDb"},
		{"escape_char", "a\x1bb", "a\uFFFDb"},
		{"mixed", "user\nfake_log_entry\r\nmore", "user\\nfake_log_entry\\r\\nmore"},
		{"empty", "", ""},
		{"unicode_preserved", "hello 世界 🔐", "hello 世界 🔐"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Input(tt.in)
			if got != tt.want {
				t.Errorf("Input(%q) = %q; want %q", tt.in, got, tt.want)
			}
		})
	}
}
