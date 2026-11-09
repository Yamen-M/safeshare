package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yamen-M/safeshare/internal/config"
	"github.com/Yamen-M/safeshare/internal/scanner"
)

func cli(stdin string, args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, strings.NewReader(stdin), &out, &errOut)
	return code, out.String(), errOut.String()
}

func tempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dir with spaces", "app log.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBriefExamples(t *testing.T) {
	tests := []struct{ name, input, want string }{
		{"header and email",
			"Authorization: Bearer sk-example-secret\nEmail: alice@example.com\n",
			"Authorization: Bearer [REDACTED:TOKEN_1]\nEmail: [REDACTED:EMAIL_1]\n"},
		{"same value same placeholder",
			"token=abc123\nretry_token=abc123\n",
			"token=[REDACTED:TOKEN_1]\nretry_token=[REDACTED:TOKEN_1]\n"},
	}
	for _, tt := range tests {
		for _, eol := range []string{"\n", "\r\n"} {
			input := strings.ReplaceAll(tt.input, "\n", eol)
			want := strings.ReplaceAll(tt.want, "\n", eol)
			code, stdout, _ := cli(input, "redact", "--stdin")
			if code != 0 || stdout != want {
				t.Errorf("%s (eol %q): exit %d\ngot  %q\nwant %q", tt.name, eol, code, stdout, want)
			}
		}
	}
}

func TestRedactIsIdempotent(t *testing.T) {
	_, once, _ := cli("token=abc123\nEmail: alice@example.com\n", "redact", "--stdin")
	code, twice, _ := cli(once, "redact", "--stdin")
	if code != 0 || twice != once {
		t.Errorf("second pass changed the text:\n%q\n%q", once, twice)
	}
}

func TestScanPrintsFindingsOnly(t *testing.T) {
	sample := filepath.Join("..", "..", "testdata", "sample.log")
	code, stdout, stderr := cli("", "scan", sample)
	if code != 1 {
		t.Fatalf("exit %d, want 1; stderr: %s", code, stderr)
	}
	if stderr != "" {
		t.Errorf("unexpected stderr: %q", stderr)
	}
	for _, original := range []string{"sk-example-secret", "alice@example.com", "abc123", "not-a-real-password", "db-01", "starting worker", "retrying in"} {
		if strings.Contains(stdout, original) {
			t.Errorf("scan output contains input text %q", original)
		}
	}
	if !strings.Contains(stdout, "bearer-token") || !strings.Contains(stdout, ":2:23:") {
		t.Errorf("expected a bearer-token finding at line 2 column 23, got:\n%s", stdout)
	}
}

func TestRedactOutputContract(t *testing.T) {
	const input = "Email: alice@example.com\n"
	code, stdout, stderr := cli(input, "redact", "--stdin")
	if code != 0 || stdout != "Email: [REDACTED:EMAIL_1]\n" {
		t.Errorf("exit %d, stdout %q", code, stdout)
	}
	if !strings.Contains(stderr, "<stdin>:1:8:") || !strings.Contains(stderr, "[REDACTED:EMAIL_1]") {
		t.Errorf("report missing from stderr: %q", stderr)
	}
	if _, _, stderr := cli(input, "redact", "--stdin", "--quiet"); stderr != "" {
		t.Errorf("--quiet still wrote to stderr: %q", stderr)
	}
	code, stdout, stderr = cli(input, "redact", "--stdin", "--dry-run", "--format", "json")
	if code != 0 || stdout != "" {
		t.Errorf("--dry-run: exit %d, stdout %q", code, stdout)
	}
	if !strings.Contains(stderr, `"redacted": false`) {
		t.Errorf("--dry-run should report findings as not redacted: %s", stderr)
	}
}

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name, stdin string
		args        []string
		want        int
	}{
		{"clean scan", "nothing to see here\n", []string{"scan", "--stdin"}, 0},
		{"findings", "Email: alice@example.com\n", []string{"scan", "--stdin"}, 1},
		{"findings but quiet", "Email: alice@example.com\n", []string{"scan", "--stdin", "--quiet"}, 1},
		{"redact with findings", "Email: alice@example.com\n", []string{"redact", "--stdin"}, 0},
		{"empty input", "", []string{"scan", "--stdin"}, 0},
		{"missing file", "", []string{"scan", filepath.Join(t.TempDir(), "nope.txt")}, 2},
		{"directory", "", []string{"scan", t.TempDir()}, 2},
		{"no input", "", []string{"scan"}, 2},
		{"file and stdin", "", []string{"scan", "--stdin", "x.txt"}, 2},
		{"unknown flag", "", []string{"scan", "--stdin", "--nope"}, 2},
		{"unknown format", "", []string{"scan", "--stdin", "--format", "xml"}, 2},
		{"sarif not yet available", "", []string{"scan", "--stdin", "--format", "sarif"}, 2},
		{"bad confidence", "", []string{"scan", "--stdin", "--confidence", "certain"}, 2},
		{"in-place with stdin", "x", []string{"redact", "--stdin", "--in-place"}, 2},
		{"missing rules file", "x", []string{"scan", "--stdin", "--rules", filepath.Join(t.TempDir(), "nope.yaml")}, 2},
		{"unknown command", "", []string{"frobnicate"}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if code, _, stderr := cli(tt.stdin, tt.args...); code != tt.want {
				t.Errorf("exit %d, want %d; stderr: %s", code, tt.want, stderr)
			}
		})
	}
}

func TestInPlace(t *testing.T) {
	const input = "Email: alice@example.com\r\n"
	path := tempFile(t, input)
	read := func() string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}

	if code, stdout, _ := cli("", "redact", path); code != 0 || stdout != "Email: [REDACTED:EMAIL_1]\r\n" {
		t.Errorf("exit %d, stdout %q", code, stdout)
	}
	if read() != input {
		t.Fatal("file changed without --in-place")
	}
	cli("", "redact", path, "--in-place", "--dry-run")
	if read() != input {
		t.Fatal("file changed during --dry-run")
	}
	code, stdout, _ := cli("", "redact", path, "--in-place")
	if code != 0 || stdout != "" || read() != "Email: [REDACTED:EMAIL_1]\r\n" {
		t.Errorf("exit %d, stdout %q, file %q", code, stdout, read())
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".safeshare-*")); len(left) != 0 {
		t.Errorf("temporary files left behind: %v", left)
	}
}

func TestInitAndConfig(t *testing.T) {
	t.Chdir(t.TempDir())
	if code, _, stderr := cli("", "init"); code != 0 {
		t.Fatalf("init: exit %d: %s", code, stderr)
	}
	if err := os.WriteFile(config.FileName, []byte("confidence: high\nallowlist:\n  exact: [sk-example-secret]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := cli("", "init"); code != 2 {
		t.Errorf("second init: exit %d, want 2", code)
	}
	if b, _ := os.ReadFile(config.FileName); !strings.HasPrefix(string(b), "confidence: high") {
		t.Error("init overwrote an existing config")
	}

	// confidence: high hides the medium email; the flag overrides the file.
	const input = "Email: alice@example.com\n"
	if code, stdout, _ := cli(input, "scan", "--stdin"); code != 0 || !strings.Contains(stdout, "warning: 1 lower-confidence") {
		t.Errorf("config confidence not applied: exit %d, %q", code, stdout)
	}
	if code, _, _ := cli(input, "scan", "--stdin", "--confidence", "medium"); code != 1 {
		t.Errorf("flag did not override config: exit %d", code)
	}
	// The allowlisted value is left alone even at low confidence.
	if _, stdout, _ := cli("Authorization: Bearer sk-example-secret\n", "redact", "--stdin", "--confidence", "low"); stdout != "Authorization: Bearer sk-example-secret\n" {
		t.Errorf("allowlist not applied: %q", stdout)
	}

	os.WriteFile(config.FileName, []byte("detectors: [pii, typo]\n"), 0o644)
	if code, _, stderr := cli(input, "scan", "--stdin"); code != 2 || !strings.Contains(stderr, "typo") {
		t.Errorf("unknown detector accepted: exit %d, %q", code, stderr)
	}
	os.WriteFile(config.FileName, []byte("detectors: [private_keys]\n"), 0o644)
	if code, _, _ := cli(input, "scan", "--stdin"); code != 0 {
		t.Errorf("detectors filter not applied: exit %d", code)
	}
}

func TestRulesAndAllowlistFlags(t *testing.T) {
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")
	allowPath := filepath.Join(dir, "allow.yaml")
	os.WriteFile(rulesPath, []byte("rules:\n  - {name: employee-id, category: employee_id, confidence: high, regex: 'EMP-\\d{6}'}\n"), 0o644)
	os.WriteFile(allowPath, []byte("exact: [alice@example.com]\n"), 0o644)

	_, stdout, _ := cli("EMP-123456 mailed alice@example.com\n", "redact", "--stdin", "--rules", rulesPath, "--allowlist", allowPath)
	if want := "[REDACTED:EMPLOYEE_ID_1] mailed alice@example.com\n"; stdout != want {
		t.Errorf("got %q, want %q", stdout, want)
	}
	code, stdout, _ := cli("", "rules", "list", "--rules", rulesPath)
	if code != 0 || !strings.Contains(stdout, "employee-id") || !strings.Contains(stdout, "github-token") {
		t.Errorf("rules list: exit %d\n%s", code, stdout)
	}

	os.WriteFile(rulesPath, []byte("rules:\n  - {name: bad, category: x, confidence: high, regex: '('}\n"), 0o644)
	if code, _, _ := cli("x", "scan", "--stdin", "--rules", rulesPath); code != 2 {
		t.Errorf("invalid rule accepted: exit %d", code)
	}
}

func TestLowConfidenceIsCountedNotDropped(t *testing.T) {
	const input = "blob Hq7Zt2Xk9Wm4Vb8Nc3Ly6Rd1Pf5Gs0Ja\n"
	code, stdout, stderr := cli(input, "redact", "--stdin")
	if code != 0 || stdout != input || !strings.Contains(stderr, "warning: 1 lower-confidence") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if _, stdout, _ := cli(input, "redact", "--stdin", "--confidence", "low"); stdout != "blob [REDACTED:SECRET_1]\n" {
		t.Errorf("got %q", stdout)
	}
}

// ---- canary leak test ----

type canary struct {
	line   string // input text containing the secret
	secret string
	body   string // part checked for fragments; the whole secret when empty
	conf   scanner.Confidence
}

// Fake credentials are assembled from pieces so that no file in this
// repository contains a string shaped like a real token. Values are random
// so that a five-character fragment cannot collide with ordinary output.
func canaries() []canary {
	c := func(conf scanner.Confidence, prefix, secret, suffix string) canary {
		return canary{line: prefix + secret + suffix, secret: secret, conf: conf}
	}
	keyBody := "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX\nq7Vt2mW9xQ4vN7bZ3cY6hJ1dF5gL0sAe"
	key := "-----BEGIN RSA PRIVATE KEY-----\n" + keyBody + "\n-----END RSA PRIVATE KEY-----"
	return []canary{
		{line: key, secret: key, body: keyBody, conf: scanner.High},
		c(scanner.High, "gh: ", "gh"+"p_"+"R8kT2mW9xQ4vN7bZ3cY6hJ1dF5gL0sAeUiOp", ""),
		c(scanner.High, "gl: ", "gl"+"pat-"+"Zx8Kq2Lm5Nv7Bw3Ty9Hd", ""),
		c(scanner.High, "slack ", "xo"+"xb-"+"482915-730164-QwErTyUiOpAsDfGh", " used"),
		c(scanner.High, "stripe ", "sk"+"_live_"+"h7G2kP9mX4qW8vB3nZ6c", ""),
		c(scanner.High, "llm ", "sk"+"-"+"pJ4nV8xK2mQ7wB9tY3zR6cH1", ""),
		c(scanner.High, "aws ", "AK"+"IA"+"J7Q2M9X4K8W3B6N5", ""),
		c(scanner.High, "jwt ", "ey"+"JhbGciOiJIUzI1NiJ9."+"ey"+"JzdWIiOiJxN3Y5In0.k3Xw9Zq2Lm8Nv5Bt7Ry1", ""),
		c(scanner.High, "DATABASE_URL=", "postgres://svc_k9x2:Vq7Lm3Zt8Wb5@db7q.example.org:5432/app", ""),
		c(scanner.Medium, "Authorization: Bearer ", "mF3kQ8vX2nW7bZ5cT9yH", ""),
		c(scanner.Medium, `db_password = "`, "Jx4#Kp9!Lw2$Rv7", `"`),
		c(scanner.Medium, "api_key: ", "Tq5Zw8Xn3Kb6Vm1Yc4", ""),
		c(scanner.Medium, "contact: ", "zq7kvw3x@m9t4hj2p.io", ""),
		c(scanner.Medium, "phone: ", "+44 7911 823456", ""),
		c(scanner.Medium, "client ", "203.0.113.77", " connected"),
		c(scanner.Medium, "host: ", "vault-7q2x.zk9.lan", ""),
		c(scanner.Medium, "card ", "4539148803436467", " declined"),
		c(scanner.Low, "blob ", "Hq7Zt2Xk9Wm4Vb8Nc3Ly6Rd1Pf5Gs0Ja", ""),
	}
}

// fragment returns a run of consecutive characters of body, one longer than
// a preview may show, that appears in out; or "" if there is none.
func fragment(out, body string) string {
	r := []rune(body)
	const n = scanner.MaxPreview + 1
	for i := 0; i+n <= len(r); i++ {
		if frag := string(r[i : i+n]); strings.Contains(out, frag) {
			return frag
		}
	}
	return ""
}

func TestCanariesNeverLeak(t *testing.T) {
	commands := [][]string{
		{"scan", "--stdin"},
		{"scan", "--stdin", "--format", "json"},
		{"redact", "--stdin"},
		{"redact", "--stdin", "--format", "json"},
		{"redact", "--stdin", "--dry-run"},
		{"scan", "--stdin", "--format", "nonsense"},
	}
	for _, level := range []scanner.Confidence{scanner.Low, scanner.Medium, scanner.High} {
		for _, eol := range []string{"\n", "\r\n"} {
			// Only canaries the chosen level is meant to catch go in; a
			// lower-confidence value passing through is by design.
			var active []canary
			var lines []string
			for _, c := range canaries() {
				if c.conf < level {
					continue
				}
				c.line = strings.ReplaceAll(c.line, "\n", eol)
				c.secret = strings.ReplaceAll(c.secret, "\n", eol)
				if c.body = strings.ReplaceAll(c.body, "\n", eol); c.body == "" {
					c.body = c.secret
				}
				active = append(active, c)
				lines = append(lines, c.line)
			}
			input := "service started" + eol + strings.Join(lines, eol) + eol + "service stopped" + eol

			for _, args := range commands {
				args = append(args, "--confidence", level.String())
				name := level.String() + " " + strings.Join(args, " ")
				_, stdout, stderr := cli(input, args...)
				out := stdout + stderr

				for _, c := range active {
					if strings.Contains(out, c.secret) {
						t.Errorf("%s: complete secret from %q is in the output", name, c.line[:6])
					} else if frag := fragment(out, c.body); frag != "" {
						t.Errorf("%s: fragment %q of a secret is in the output", name, frag)
					}
				}

				if args[0] == "scan" && args[len(args)-3] == "json" {
					var report struct {
						Findings []struct {
							Preview string `json:"preview"`
						} `json:"findings"`
					}
					if err := json.Unmarshal([]byte(stdout), &report); err != nil {
						t.Fatalf("%s: %v", name, err)
					}
					if len(report.Findings) < len(active) {
						t.Errorf("%s: %d findings for %d canaries", name, len(report.Findings), len(active))
					}
					for _, f := range report.Findings {
						shown, masked := strings.CutSuffix(f.Preview, "***")
						if !masked || len([]rune(shown)) > scanner.MaxPreview {
							t.Errorf("%s: preview %q is not masked", name, f.Preview)
						}
					}
				}
			}
		}
	}
}

func TestErrorsDoNotEchoInput(t *testing.T) {
	// A secret passed where a file name is expected is the user's own
	// argument, so it may be echoed; input content must never be.
	path := tempFile(t, "Email: alice@example.com\n")
	_, stdout, stderr := cli("", "scan", path, "--format", "xml")
	if strings.Contains(stdout+stderr, "alice") {
		t.Errorf("error output contains input: %q", stdout+stderr)
	}
}
