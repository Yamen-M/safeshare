package rules

import (
	"strings"
	"testing"
)

func TestBuiltin(t *testing.T) {
	rs := Builtin()
	if len(rs) == 0 {
		t.Fatal("no built-in rules")
	}
	seen := map[string]bool{}
	for _, r := range rs {
		if seen[r.Name] {
			t.Errorf("duplicate rule name %s", r.Name)
		}
		seen[r.Name] = true
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name, yaml, wantErr string
	}{
		{"valid", "rules:\n  - {name: emp-id, category: employee_id, confidence: high, regex: 'EMP-\\d{6}'}", ""},
		{"empty file", "", ""},
		{"disabled rule needs no regex", "rules:\n  - {name: email, enabled: false}", ""},
		{"invalid regex", "rules:\n  - {name: bad, category: x, confidence: low, regex: '(unclosed'}", "missing closing"},
		{"matches empty", "rules:\n  - {name: bad, category: x, confidence: low, regex: 'a*'}", "empty string"},
		{"bad confidence", "rules:\n  - {name: bad, category: x, confidence: certain, regex: 'abc'}", "invalid confidence"},
		{"bad category", "rules:\n  - {name: bad, category: 'Has Space', confidence: low, regex: 'abc'}", "category"},
		{"missing name", "rules:\n  - {category: x, confidence: low, regex: 'abc'}", "name"},
		{"unknown key", "rules:\n  - {name: bad, category: x, confidence: low, regexp: 'abc'}", "regexp"},
		{"too long", "rules:\n  - {name: bad, category: x, confidence: low, regex: '" + strings.Repeat("a", 1001) + "'}", "between 1 and"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("error %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}
