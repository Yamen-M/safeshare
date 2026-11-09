// Package output formats scan reports. Formatters only ever see findings,
// which hold no raw values, so they cannot print one.
package output

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/Yamen-M/safeshare/internal/scanner"
)

// Report is the result of scanning one input.
type Report struct {
	Source   string            `json:"source"`
	Findings []scanner.Finding `json:"findings"`
	// Hidden counts findings below the confidence threshold. They are not
	// listed and were not redacted.
	Hidden int `json:"hidden_below_confidence"`
}

// Formatter writes a report.
type Formatter interface {
	Format(w io.Writer, r Report) error
}

// New returns the formatter for a --format value.
func New(format string) (Formatter, error) {
	switch format {
	case "", "text":
		return text{}, nil
	case "json":
		return jsonFormat{}, nil
	case "sarif":
		return nil, fmt.Errorf("format sarif is not available yet: use text or json")
	}
	return nil, fmt.Errorf("unknown format %q: use text or json", format)
}

type text struct{}

func (text) Format(w io.Writer, r Report) error {
	for _, f := range r.Findings {
		line := fmt.Sprintf("%s:%d:%d: %s %s (%s) %s", r.Source, f.Line, f.Column, f.Confidence, f.Detector, f.Category, f.Preview)
		if f.Redacted {
			line += " -> " + f.Placeholder
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "%d finding(s) in %s\n", len(r.Findings), r.Source); err != nil {
		return err
	}
	if r.Hidden > 0 {
		_, err := fmt.Fprintf(w, "warning: %d lower-confidence finding(s) were not shown or redacted; rerun with --confidence low to review them\n", r.Hidden)
		return err
	}
	return nil
}

type jsonFormat struct{}

func (jsonFormat) Format(w io.Writer, r Report) error {
	if r.Findings == nil {
		r.Findings = []scanner.Finding{} // encode as [] rather than null
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false) // keep "<stdin>" readable
	return enc.Encode(r)
}
