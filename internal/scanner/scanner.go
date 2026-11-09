// Package scanner turns detector matches into findings.
//
// A Finding never holds the matched text: only offsets, a masked preview and
// metadata. Anything that needs the value reads it from the input by offset.
package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Confidence says how sure a detector is that a match is sensitive.
type Confidence int

const (
	Low Confidence = iota + 1
	Medium
	High
)

func (c Confidence) String() string {
	switch c {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	}
	return "unknown"
}

// MarshalText makes Confidence encode as its name in JSON.
func (c Confidence) MarshalText() ([]byte, error) { return []byte(c.String()), nil }

// ParseConfidence accepts low, medium or high.
func ParseConfidence(s string) (Confidence, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return Low, nil
	case "medium":
		return Medium, nil
	case "high":
		return High, nil
	}
	return 0, fmt.Errorf("invalid confidence %q: use low, medium or high", s)
}

// Match is a half-open byte range [Start, End) in the scanned input.
type Match struct{ Start, End int }

// Detector finds one kind of sensitive value.
type Detector interface {
	Name() string
	Category() string
	Confidence() Confidence
	Find(input []byte) []Match
}

// Finding describes one detected value without containing it.
type Finding struct {
	ID         string     `json:"id"`
	Detector   string     `json:"detector"`
	Category   string     `json:"category"`
	Confidence Confidence `json:"confidence"`
	// Start and End are 0-based byte offsets into the input.
	Start int `json:"start"`
	End   int `json:"end"`
	// Line and Column are 1-based; Column counts Unicode code points.
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Preview     string `json:"preview"`
	Placeholder string `json:"placeholder,omitempty"`
	Redacted    bool   `json:"redacted"`
}

// StdinPath is the source name used for piped input, so finding IDs for the
// same piped text are always the same.
const StdinPath = "<stdin>"

// placeholder matches text SafeShare already redacted, so running it twice
// over the same text changes nothing.
var placeholder = regexp.MustCompile(`^\[REDACTED:[A-Z0-9_]+\]$`)

// Scan runs every detector over input and returns findings ordered by
// position with no overlaps. allowed may be nil; a match it accepts is dropped.
func Scan(path string, input []byte, detectors []Detector, allowed func([]byte) bool) []Finding {
	var all []Finding
	for _, d := range detectors {
		for _, m := range d.Find(input) {
			if m.Start < 0 || m.End > len(input) || m.Start >= m.End {
				continue
			}
			value := input[m.Start:m.End]
			if placeholder.Match(value) || (allowed != nil && allowed(value)) {
				continue
			}
			all = append(all, Finding{
				Detector: d.Name(), Category: d.Category(), Confidence: d.Confidence(),
				Start: m.Start, End: m.End,
			})
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Start < all[j].Start })

	// Overlapping matches are merged into one finding that covers all of them,
	// so no piece of a detected value is left outside a redaction. The merged
	// finding takes its name from the most confident, then longest, match.
	var merged []Finding
	for _, f := range all {
		if n := len(merged); n > 0 && f.Start < merged[n-1].End {
			last := &merged[n-1]
			start, end := last.Start, max(last.End, f.End)
			if better(f, *last) {
				*last = f
			}
			last.Start, last.End = start, end
			continue
		}
		merged = append(merged, f)
	}

	line, lineStart, pos := 1, 0, 0
	if strings.HasPrefix(string(input[:min(len(input), 3)]), "\xEF\xBB\xBF") {
		lineStart = 3 // a UTF-8 byte-order mark is not a column
	}
	for i := range merged {
		f := &merged[i]
		for ; pos < f.Start; pos++ {
			if input[pos] == '\n' {
				line++
				lineStart = pos + 1
			}
		}
		f.Line = line
		f.Column = utf8.RuneCount(input[lineStart:f.Start]) + 1
		f.Preview = Mask(input[f.Start:f.End])
		f.ID = findingID(f.Detector, path, f.Start)
	}
	return merged
}

func better(a, b Finding) bool {
	if a.Confidence != b.Confidence {
		return a.Confidence > b.Confidence
	}
	return a.End-a.Start > b.End-b.Start
}

// MaxPreview is the most characters of a value a preview may reveal.
const MaxPreview = 4

// Mask returns a preview that reveals at most the first MaxPreview characters
// and never more than a quarter of the value. Values shorter than 8
// characters reveal nothing.
func Mask(value []byte) string {
	n := utf8.RuneCount(value)
	show := min(n/4, MaxPreview)
	if n < 8 {
		show = 0
	}
	var b strings.Builder
	for i := 0; i < show; i++ {
		r, size := utf8.DecodeRune(value)
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			break
		}
		b.WriteRune(r)
		value = value[size:]
	}
	b.WriteString("***")
	return b.String()
}

// findingID hashes where a finding is, never what it is: a hash of a short
// secret such as a phone number could be brute-forced.
func findingID(detector, path string, start int) string {
	path = strings.ReplaceAll(path, `\`, "/")
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", detector, path, start)))
	return hex.EncodeToString(sum[:6])
}
