package detectors

import (
	"strings"
	"testing"

	"github.com/Yamen-M/safeshare/internal/rules"
	"github.com/Yamen-M/safeshare/internal/scanner"
)

// validCard appends the Luhn check digit to 15 made-up digits.
func validCard() string {
	const body = "453914880343646"
	for d := '0'; d <= '9'; d++ {
		if c := body + string(d); luhn([]byte(c)) {
			return c
		}
	}
	panic("unreachable")
}

// Fake credentials are assembled from pieces so that no file in this
// repository contains a string shaped like a real token.
func TestBuiltinDetection(t *testing.T) {
	r36 := "R8kT2mW9xQ4vN7bZ3cY6hJ1dF5gL0sAeUiOp"
	tests := []struct {
		name, input, detector, value string
	}{
		{"private key", "x\n-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB\n-----END RSA PRIVATE KEY-----\ny", "private-key",
			"-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJB\n-----END RSA PRIVATE KEY-----"},
		{"private key CRLF", "-----BEGIN PRIVATE KEY-----\r\nMIIBOgIBAAJB\r\n-----END PRIVATE KEY-----\r\n", "private-key",
			"-----BEGIN PRIVATE KEY-----\r\nMIIBOgIBAAJB\r\n-----END PRIVATE KEY-----"},
		{"truncated private key", "-----BEGIN EC PRIVATE KEY-----\nMIIBOgIBAAJB\n", "private-key",
			"-----BEGIN EC PRIVATE KEY-----\nMIIBOgIBAAJB\n"},
		{"jwt", "jwt=" + "ey" + "JhbGciOiJIUzI1NiJ9." + "ey" + "JzdWIiOiJxN3Y5In0.k3Xw9Zq2Lm8Nv5Bt7Ry1", "jwt",
			"ey" + "JhbGciOiJIUzI1NiJ9." + "ey" + "JzdWIiOiJxN3Y5In0.k3Xw9Zq2Lm8Nv5Bt7Ry1"},
		{"aws access key id", "id " + "AK" + "IAJ7Q2M9X4K8W3B6N5", "aws-access-key-id", "AK" + "IAJ7Q2M9X4K8W3B6N5"},
		{"aws secret", "aws_secret_access_key = " + r36 + "Ab1+", "aws-secret-access-key", r36 + "Ab1+"},
		{"gcp api key", "key " + "AI" + "za" + r36[:35], "gcp-api-key", "AI" + "za" + r36[:35]},
		{"azure storage key", "AccountName=x;AccountKey=" + r36 + "abcd==;", "azure-storage-key", r36 + "abcd=="},
		{"github token", "gh" + "p_" + r36, "github-token", "gh" + "p_" + r36},
		{"gitlab token", "gl" + "pat-Zx8Kq2Lm5Nv7Bw3Ty9Hd", "gitlab-token", "gl" + "pat-Zx8Kq2Lm5Nv7Bw3Ty9Hd"},
		{"slack token", "xo" + "xb-482915-730164-QwErTyUiOpAsDfGh", "slack-token", "xo" + "xb-482915-730164-QwErTyUiOpAsDfGh"},
		{"stripe key", "sk" + "_live_h7G2kP9mX4qW8vB3nZ6c", "stripe-key", "sk" + "_live_h7G2kP9mX4qW8vB3nZ6c"},
		{"openai-style key", "sk" + "-pJ4nV8xK2mQ7wB9tY3zR6cH1", "openai-style-key", "sk" + "-pJ4nV8xK2mQ7wB9tY3zR6cH1"},
		{"database url", "DATABASE_URL=postgres://svc:Vq7Lm3Zt@db.example.org:5432/app", "url-credentials",
			"postgres://svc:Vq7Lm3Zt@db.example.org:5432/app"},
		{"bearer", "Authorization: Bearer sk-example-secret", "bearer-token", "sk-example-secret"},
		{"token assignment", "retry_token=abc123", "token-assignment", "abc123"},
		{"json api key", `{"api_key": "Tq5Zw8Xn3Kb6"}`, "token-assignment", "Tq5Zw8Xn3Kb6"},
		{"password assignment", "DB_PASSWORD: hunter2!", "password-assignment", "hunter2!"},
		{"email", "Email: alice@example.com", "email", "alice@example.com"},
		{"phone international", "call +44 7911 823456 now", "phone", "+44 7911 823456"},
		{"phone national", "call (555) 123-4567 now", "phone", "(555) 123-4567"},
		{"ipv4", "client 203.0.113.77 connected", "ipv4", "203.0.113.77"},
		{"internal hostname", "dial tcp db-01.prod.internal:5432", "internal-hostname", "db-01.prod.internal"},
		{"credit card", "card " + validCard(), "credit-card", validCard()},
		{"high entropy", "blob Hq7Zt2Xk9Wm4Vb8Nc3Ly6Rd1Pf5Gs0Ja", "high-entropy", "Hq7Zt2Xk9Wm4Vb8Nc3Ly6Rd1Pf5Gs0Ja"},
	}
	dets, err := All(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, f := range scanner.Scan("f", []byte(tt.input), dets, nil) {
				value := tt.input[f.Start:f.End]
				if f.Detector == tt.detector && value == tt.value {
					return
				}
				got = append(got, f.Detector+" at "+f.Preview)
			}
			t.Errorf("want %s to cover the whole value; got %v", tt.detector, got)
		})
	}
}

func TestOrdinaryTextHasNoFindings(t *testing.T) {
	dets, _ := All(nil, 0)
	for _, input := range []string{
		"Build finished in 12.5s with 3 warnings at 2024-01-15 10:30:00",
		"panic: runtime error: index out of range [5] with length 3",
		"GET /api/v2/users?page=2 200 OK (41 ms)",
		"see internal/scanner/scanner.go:120 for the overlap handling code",
		"order 1234567890123 shipped", // 13 digits, fails the Luhn check
	} {
		if got := scanner.Scan("f", []byte(input), dets, nil); len(got) != 0 {
			t.Errorf("%q: unexpected %s finding", input, got[0].Detector)
		}
	}
}

func TestCustomRules(t *testing.T) {
	off := false
	custom := []rules.Rule{
		{Name: "employee-id", Category: "employee_id", Confidence: "high", Regex: `EMP-\d{6}`},
		{Name: "email", Enabled: &off},
	}
	dets, err := All(custom, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := scanner.Scan("f", []byte("EMP-123456 wrote to alice@example.com"), dets, nil)
	if len(got) != 1 || got[0].Detector != "employee-id" {
		t.Errorf("got %+v, want only employee-id", got)
	}
}

func TestEntropyThreshold(t *testing.T) {
	repetitive := []byte("abababababab1212121212ab")
	if entropy(repetitive) >= DefaultEntropyThreshold {
		t.Error("repetitive string scored as high entropy")
	}
	dets, _ := All(nil, 6) // nothing made of 64 symbols can reach 6 bits
	for _, f := range scanner.Scan("f", []byte(strings.Repeat("Hq7Zt2Xk9Wm4", 3)), dets, nil) {
		if f.Detector == "high-entropy" {
			t.Error("threshold was not applied")
		}
	}
}
