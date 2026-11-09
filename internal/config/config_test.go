package config

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dir with spaces", FileName)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad(t *testing.T) {
	if c, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err != nil || c.Confidence != "" {
		t.Errorf("missing file: got %+v, %v", c, err)
	}
	c, err := Load(write(t, Template))
	if err != nil {
		t.Fatalf("template does not load: %v", err)
	}
	if c.Confidence != "medium" || len(c.Allowlist.Exact) != 2 {
		t.Errorf("template parsed as %+v", c)
	}
	// CRLF files, as written by Windows editors, load the same way.
	if _, err := Load(write(t, "version: 1\r\nconfidence: high\r\n")); err != nil {
		t.Errorf("CRLF config: %v", err)
	}
	if _, err := Load(write(t, "confidense: high\n")); err == nil {
		t.Error("misspelled key was accepted")
	}
	if _, err := Load(write(t, "version: 2\n")); err == nil {
		t.Error("future version was accepted")
	}
}

func TestAllowlistMatcher(t *testing.T) {
	a := Allowlist{Exact: []string{"example.com"}, Regex: []string{`10\.0\.\d+\.\d+`}}
	match, err := a.Matcher()
	if err != nil {
		t.Fatal(err)
	}
	for value, want := range map[string]bool{
		"example.com":       true,
		"alice@example.com": false, // exact means the whole value
		"10.0.3.4":          true,
		"210.0.3.45":        false, // regex is anchored
		"anything":          false,
	} {
		if got := match([]byte(value)); got != want {
			t.Errorf("match(%q) = %v, want %v", value, got, want)
		}
	}
	if _, err := (Allowlist{Regex: []string{"("}}).Matcher(); err == nil {
		t.Error("invalid regex was accepted")
	}
}

func TestCategories(t *testing.T) {
	if Categories(nil) != nil {
		t.Error("empty list should mean everything")
	}
	got := Categories([]string{"pii", "private_keys", "token"})
	for _, want := range []string{"email", "phone", "ip", "hostname", "card", "private_key", "token"} {
		if !got[want] {
			t.Errorf("missing %s", want)
		}
	}
	if got["password"] {
		t.Error("password should not be enabled")
	}
}
