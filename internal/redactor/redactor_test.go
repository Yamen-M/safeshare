package redactor

import (
	"strings"
	"testing"

	"github.com/Yamen-M/safeshare/internal/scanner"
)

// find builds findings for each occurrence of the given values, in order.
func find(input string, category string, values ...string) []scanner.Finding {
	var out []scanner.Finding
	for off := 0; off < len(input); {
		best, bestAt := "", -1
		for _, v := range values {
			if i := strings.Index(input[off:], v); i >= 0 && (bestAt < 0 || i < bestAt) {
				best, bestAt = v, i
			}
		}
		if bestAt < 0 {
			break
		}
		out = append(out, scanner.Finding{Category: category, Start: off + bestAt, End: off + bestAt + len(best)})
		off += bestAt + len(best)
	}
	return out
}

func TestRedact(t *testing.T) {
	tests := []struct {
		name, input, want string
		values            []string
	}{
		{"same value same placeholder", "token=abc123\nretry_token=abc123\n",
			"token=[REDACTED:TOKEN_1]\nretry_token=[REDACTED:TOKEN_1]\n", []string{"abc123"}},
		{"CRLF preserved", "token=abc123\r\nretry_token=abc123\r\n",
			"token=[REDACTED:TOKEN_1]\r\nretry_token=[REDACTED:TOKEN_1]\r\n", []string{"abc123"}},
		{"different values count up", "a=one1 b=two2 c=one1",
			"a=[REDACTED:TOKEN_1] b=[REDACTED:TOKEN_2] c=[REDACTED:TOKEN_1]", []string{"one1", "two2"}},
		{"no findings", "  nothing\there \r\n", "  nothing\there \r\n", nil},
		{"value at both ends", "abc123 mid abc123", "[REDACTED:TOKEN_1] mid [REDACTED:TOKEN_1]", []string{"abc123"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := find(tt.input, "token", tt.values...)
			got := string(Redact([]byte(tt.input), findings))
			if got != tt.want {
				t.Errorf("got  %q\nwant %q", got, tt.want)
			}
			for _, f := range findings {
				if !f.Redacted || f.Placeholder == "" {
					t.Errorf("finding at %d not marked redacted", f.Start)
				}
			}
		})
	}
}

func TestPlaceholderCountersArePerCategory(t *testing.T) {
	input := "alice@example.com abc123"
	findings := []scanner.Finding{
		{Category: "email", Start: 0, End: 17},
		{Category: "token", Start: 18, End: 24},
	}
	if got, want := string(Redact([]byte(input), findings)), "[REDACTED:EMAIL_1] [REDACTED:TOKEN_1]"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
