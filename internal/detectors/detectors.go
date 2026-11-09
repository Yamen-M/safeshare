// Package detectors holds the scanner.Detector implementations: regex rules,
// credit-card-like numbers and high-entropy strings.
package detectors

import (
	"math"
	"regexp"

	"github.com/Yamen-M/safeshare/internal/rules"
	"github.com/Yamen-M/safeshare/internal/scanner"
)

// DefaultEntropyThreshold is in bits per character.
const DefaultEntropyThreshold = 3.5

// All returns the built-in detectors plus custom rules. A custom rule with the
// name of a built-in rule replaces it, and `enabled: false` removes it.
func All(custom []rules.Rule, entropyThreshold float64) ([]scanner.Detector, error) {
	merged := rules.Builtin()
	index := map[string]int{}
	for i, r := range merged {
		index[r.Name] = i
	}
	for _, r := range custom {
		if i, ok := index[r.Name]; ok {
			merged[i] = r
		} else {
			index[r.Name] = len(merged)
			merged = append(merged, r)
		}
	}

	var out []scanner.Detector
	for _, r := range merged {
		if !r.IsEnabled() {
			continue
		}
		re, conf, err := r.Compile()
		if err != nil {
			return nil, err
		}
		out = append(out, regexDetector{r.Name, r.Category, conf, re})
	}
	if entropyThreshold <= 0 {
		entropyThreshold = DefaultEntropyThreshold
	}
	return append(out, cardDetector{}, entropyDetector{entropyThreshold}), nil
}

type regexDetector struct {
	name, category string
	conf           scanner.Confidence
	re             *regexp.Regexp
}

func (d regexDetector) Name() string                   { return d.name }
func (d regexDetector) Category() string               { return d.category }
func (d regexDetector) Confidence() scanner.Confidence { return d.conf }
func (d regexDetector) Find(input []byte) []scanner.Match {
	var out []scanner.Match
	for _, loc := range d.re.FindAllSubmatchIndex(input, -1) {
		start, end := loc[0], loc[1]
		if len(loc) >= 4 && loc[2] >= 0 { // first capture group is the value
			start, end = loc[2], loc[3]
		}
		out = append(out, scanner.Match{Start: start, End: end})
	}
	return out
}

// cardDetector reports 13 to 19 digit numbers that pass the Luhn check.
// ponytail: about one random number in ten passes Luhn, so long numeric IDs
// can be flagged; add issuer-prefix checks if false positives matter.
type cardDetector struct{}

var cardCandidate = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)

func (cardDetector) Name() string                   { return "credit-card" }
func (cardDetector) Category() string               { return "card" }
func (cardDetector) Confidence() scanner.Confidence { return scanner.Medium }
func (cardDetector) Find(input []byte) []scanner.Match {
	var out []scanner.Match
	for _, loc := range cardCandidate.FindAllIndex(input, -1) {
		if luhn(input[loc[0]:loc[1]]) {
			out = append(out, scanner.Match{Start: loc[0], End: loc[1]})
		}
	}
	return out
}

// luhn ignores anything that is not a digit.
func luhn(b []byte) bool {
	sum, double := 0, false
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < '0' || b[i] > '9' {
			continue
		}
		d := int(b[i] - '0')
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// entropyDetector reports long random-looking strings.
// ponytail: naive heuristic (20+ characters, a letter and a digit, Shannon
// entropy over the threshold), so it is low confidence and will flag hashes
// and IDs; a trained classifier is the upgrade path.
type entropyDetector struct{ threshold float64 }

// "=" is only accepted as trailing base64 padding, so "key=value" is not
// swallowed whole and the key name stays readable.
var entropyCandidate = regexp.MustCompile(`[A-Za-z0-9+/_-]{20,}={0,2}`)

func (entropyDetector) Name() string                   { return "high-entropy" }
func (entropyDetector) Category() string               { return "secret" }
func (entropyDetector) Confidence() scanner.Confidence { return scanner.Low }
func (d entropyDetector) Find(input []byte) []scanner.Match {
	var out []scanner.Match
	for _, loc := range entropyCandidate.FindAllIndex(input, -1) {
		if s := input[loc[0]:loc[1]]; mixed(s) && entropy(s) >= d.threshold {
			out = append(out, scanner.Match{Start: loc[0], End: loc[1]})
		}
	}
	return out
}

func mixed(b []byte) bool {
	var letter, digit bool
	for _, c := range b {
		letter = letter || (c|0x20 >= 'a' && c|0x20 <= 'z')
		digit = digit || (c >= '0' && c <= '9')
	}
	return letter && digit
}

// entropy is the Shannon entropy of b in bits per byte.
func entropy(b []byte) float64 {
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	var h float64
	for _, n := range counts {
		if n > 0 {
			p := float64(n) / float64(len(b))
			h -= p * math.Log2(p)
		}
	}
	return h
}
