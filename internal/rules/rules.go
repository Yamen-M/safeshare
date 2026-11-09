// Package rules loads and validates detection rules written in YAML.
package rules

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/Yamen-M/safeshare/internal/scanner"
	"gopkg.in/yaml.v3"
)

//go:embed builtin.yaml
var builtinYAML []byte

// Rule is one regex detector. Built-in and custom rules share this shape.
type Rule struct {
	Name       string `yaml:"name"`
	Category   string `yaml:"category"`
	Regex      string `yaml:"regex"`
	Confidence string `yaml:"confidence"`
	Enabled    *bool  `yaml:"enabled"`
}

// IsEnabled reports whether the rule should run; rules are on by default.
func (r Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

const maxRegexLen = 1000

var (
	nameRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	categoryRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
)

// Compile validates the rule and returns its compiled regex and confidence.
func (r Rule) Compile() (*regexp.Regexp, scanner.Confidence, error) {
	fail := func(format string, a ...any) (*regexp.Regexp, scanner.Confidence, error) {
		return nil, 0, fmt.Errorf("rule %q: %s", r.Name, fmt.Sprintf(format, a...))
	}
	if !nameRe.MatchString(r.Name) {
		return fail("name must be lowercase letters, digits and hyphens")
	}
	if !categoryRe.MatchString(r.Category) {
		return fail("category must be lowercase letters, digits and underscores")
	}
	conf, err := scanner.ParseConfidence(r.Confidence)
	if err != nil {
		return fail("%v", err)
	}
	if r.Regex == "" || len(r.Regex) > maxRegexLen {
		return fail("regex must be between 1 and %d characters", maxRegexLen)
	}
	re, err := regexp.Compile(r.Regex)
	if err != nil {
		return fail("%v", err)
	}
	if re.MatchString("") {
		return fail("regex matches the empty string, so it would match everywhere")
	}
	return re, conf, nil
}

// Parse reads a rule file. Unknown keys are errors, so a typo cannot silently
// turn a rule off. Disabled rules only need a name.
func Parse(data []byte) ([]Rule, error) {
	var f struct {
		Rules []Rule `yaml:"rules"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	for _, r := range f.Rules {
		if !r.IsEnabled() {
			if !nameRe.MatchString(r.Name) {
				return nil, fmt.Errorf("rule %q: name must be lowercase letters, digits and hyphens", r.Name)
			}
			continue
		}
		if _, _, err := r.Compile(); err != nil {
			return nil, err
		}
	}
	return f.Rules, nil
}

// Load reads a rule file from disk.
func Load(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rs, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return rs, nil
}

// Builtin returns the rules shipped with SafeShare.
func Builtin() []Rule {
	rs, err := Parse(builtinYAML)
	if err != nil {
		panic("safeshare: invalid built-in rules: " + err.Error()) // caught by TestBuiltin
	}
	return rs
}
