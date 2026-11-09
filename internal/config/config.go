// Package config reads .safeshare.yaml and allowlist files.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// FileName is looked up in the current directory.
const FileName = ".safeshare.yaml"

// Allowlist names values that must never be reported.
type Allowlist struct {
	Exact []string `yaml:"exact"`
	Regex []string `yaml:"regex"`
}

// Config is the content of .safeshare.yaml. Every field is optional.
type Config struct {
	Version          int       `yaml:"version"`
	Confidence       string    `yaml:"confidence"`
	Detectors        []string  `yaml:"detectors"`
	EntropyThreshold float64   `yaml:"entropy_threshold"`
	Allowlist        Allowlist `yaml:"allowlist"`
}

// Template is what `safeshare init` writes.
const Template = `# SafeShare configuration. Every setting is optional.
version: 1

# Findings below this level are counted but not shown or redacted.
# One of: low, medium, high.
confidence: medium

# Leave empty to run every detector. Otherwise list groups (tokens, pii,
# private_keys) or single categories from "safeshare rules list".
detectors: []

# Minimum Shannon entropy, in bits per character, for the high-entropy detector.
entropy_threshold: 3.5

allowlist:
  # Values that are never reported. Each must equal the whole detected value.
  exact:
    - 127.0.0.1
    - 0.0.0.0
  # Regular expressions (Go/RE2 syntax). Each must match the whole detected value.
  regex: []
`

// strict decodes YAML and rejects unknown keys, so a misspelled setting is an
// error instead of being silently ignored.
func strict(path string, into any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(into); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// Load reads the config at path. A missing file is not an error.
func Load(path string) (Config, error) {
	var c Config
	err := strict(path, &c)
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err == nil && c.Version > 1 {
		err = fmt.Errorf("%s: version %d is newer than this SafeShare understands", path, c.Version)
	}
	return c, err
}

// LoadAllowlist reads a standalone allowlist file.
func LoadAllowlist(path string) (Allowlist, error) {
	var a Allowlist
	return a, strict(path, &a)
}

// Merge returns the entries of both allowlists.
func (a Allowlist) Merge(b Allowlist) Allowlist {
	return Allowlist{
		Exact: append(append([]string{}, a.Exact...), b.Exact...),
		Regex: append(append([]string{}, a.Regex...), b.Regex...),
	}
}

// Matcher compiles the allowlist. Regexes are anchored to the whole value so
// a loose pattern cannot allow more than its author meant.
func (a Allowlist) Matcher() (func([]byte) bool, error) {
	exact := map[string]bool{}
	for _, e := range a.Exact {
		exact[e] = true
	}
	var res []*regexp.Regexp
	for _, r := range a.Regex {
		re, err := regexp.Compile(`^(?:` + r + `)$`)
		if err != nil {
			return nil, fmt.Errorf("allowlist regex %q: %w", r, err)
		}
		res = append(res, re)
	}
	return func(value []byte) bool {
		if exact[string(value)] {
			return true
		}
		for _, re := range res {
			if re.Match(value) {
				return true
			}
		}
		return false
	}, nil
}

var groups = map[string][]string{
	"tokens":       {"token", "password", "secret", "connection_string"},
	"pii":          {"email", "phone", "ip", "hostname", "card"},
	"private_keys": {"private_key"},
}

// Categories expands group names in a detectors list into a set of categories.
// It returns nil for an empty list, meaning "everything".
func Categories(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	set := map[string]bool{}
	for _, n := range names {
		if members, ok := groups[n]; ok {
			for _, m := range members {
				set[m] = true
			}
		} else {
			set[n] = true
		}
	}
	return set
}
