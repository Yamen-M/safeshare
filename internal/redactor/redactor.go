// Package redactor replaces detected values with deterministic placeholders.
package redactor

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/Yamen-M/safeshare/internal/scanner"
)

// Redact returns input with every finding replaced by a placeholder such as
// [REDACTED:TOKEN_1], and records the placeholder on each finding. The same
// value always gets the same placeholder within one call. Everything outside
// the findings, including line endings, is copied through untouched.
//
// findings must be ordered and non-overlapping, as scanner.Scan returns them.
func Redact(input []byte, findings []scanner.Finding) []byte {
	var out bytes.Buffer
	placeholders := map[string]string{} // value -> placeholder; lives only for this call
	counts := map[string]int{}
	pos := 0
	for i := range findings {
		f := &findings[i]
		if f.Start < pos || f.End > len(input) {
			continue // not produced by scanner.Scan; leave it marked unredacted
		}
		value := string(input[f.Start:f.End])
		ph, ok := placeholders[value]
		if !ok {
			label := strings.ToUpper(f.Category)
			counts[label]++
			ph = fmt.Sprintf("[REDACTED:%s_%d]", label, counts[label])
			placeholders[value] = ph
		}
		out.Write(input[pos:f.Start])
		out.WriteString(ph)
		pos = f.End
		f.Placeholder, f.Redacted = ph, true
	}
	out.Write(input[pos:])
	return out.Bytes()
}
