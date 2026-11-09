package scanner

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

// literal finds every occurrence of a fixed string.
type literal struct {
	name, text string
	conf       Confidence
}

func (l literal) Name() string           { return l.name }
func (l literal) Category() string       { return "test" }
func (l literal) Confidence() Confidence { return l.conf }
func (l literal) Find(input []byte) []Match {
	var out []Match
	for off := 0; ; {
		i := bytes.Index(input[off:], []byte(l.text))
		if i < 0 {
			return out
		}
		out = append(out, Match{off + i, off + i + len(l.text)})
		off += i + len(l.text)
	}
}

func TestLineAndColumn(t *testing.T) {
	d := []Detector{literal{"x", "SECRETVALUE", High}}
	tests := []struct {
		name, input string
		line, col   int
		start       int
	}{
		{"first line", "SECRETVALUE", 1, 1, 0},
		{"LF", "a\nbc SECRETVALUE\n", 2, 4, 5},
		{"CRLF", "a\r\nbc SECRETVALUE\r\n", 2, 4, 6},
		{"byte-order mark is not a column", "\xEF\xBB\xBFab SECRETVALUE", 1, 4, 6},
		{"multibyte before match", "héllo 🙂 SECRETVALUE", 1, 9, 12},
		{"multibyte on earlier CRLF line", "é\r\n🙂\r\nx SECRETVALUE", 3, 3, 12}, // 2+2+4+2+2 bytes
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Scan("f", []byte(tt.input), d, nil)
			if len(got) != 1 {
				t.Fatalf("got %d findings, want 1", len(got))
			}
			f := got[0]
			if f.Line != tt.line || f.Column != tt.col || f.Start != tt.start {
				t.Errorf("line %d col %d start %d, want line %d col %d start %d",
					f.Line, f.Column, f.Start, tt.line, tt.col, tt.start)
			}
			if tt.input[f.Start:f.End] != "SECRETVALUE" {
				t.Errorf("offsets select %q", tt.input[f.Start:f.End])
			}
		})
	}
}

func TestOverlapsMergeIntoOneFinding(t *testing.T) {
	input := []byte("xx abcdefgh yy")
	got := Scan("f", input, []Detector{
		literal{"low-long", "abcdef", Low},
		literal{"high-short", "efgh", High},
	}, nil)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Detector != "high-short" || string(input[got[0].Start:got[0].End]) != "abcdefgh" {
		t.Errorf("got %s covering %q", got[0].Detector, input[got[0].Start:got[0].End])
	}
}

func TestMask(t *testing.T) {
	tests := []struct{ value, want string }{
		{"", "***"},
		{"abc1234", "***"},              // under 8 characters: nothing shown
		{"abcd1234", "ab***"},           // a quarter of 8
		{"abcdefgh12345678", "abcd***"}, // capped at 4
		{strings.Repeat("z", 100), "zzzz***"},
		{"\x00\x01binary-data-here", "***"}, // unprintable bytes are not echoed
	}
	for _, tt := range tests {
		if got := Mask([]byte(tt.value)); got != tt.want {
			t.Errorf("Mask(%q) = %q, want %q", tt.value, got, tt.want)
		}
	}
}

func TestFindingIDs(t *testing.T) {
	d := []Detector{literal{"x", "SECRETVALUE", High}}
	in := []byte("a SECRETVALUE b SECRETVALUE")
	a := Scan(StdinPath, in, d, nil)
	b := Scan(StdinPath, in, d, nil)
	if !reflect.DeepEqual(a, b) {
		t.Error("same input produced different findings")
	}
	if a[0].ID == a[1].ID {
		t.Error("two findings share an ID")
	}
	win := Scan(`logs\app.log`, in, d, nil)
	unix := Scan("logs/app.log", in, d, nil)
	if win[0].ID != unix[0].ID {
		t.Error("ID differs between Windows and Unix path separators")
	}
}

func TestAllowedAndPlaceholdersAreSkipped(t *testing.T) {
	d := []Detector{literal{"x", "[REDACTED:TOKEN_1]", High}, literal{"y", "keepme", High}}
	allowed := func(v []byte) bool { return string(v) == "keepme" }
	if got := Scan("f", []byte("a [REDACTED:TOKEN_1] keepme"), d, allowed); len(got) != 0 {
		t.Errorf("got %d findings, want 0", len(got))
	}
}

func TestFindingHasNoRawValueField(t *testing.T) {
	// Every string field is listed here on purpose. Adding one that carries
	// the matched text must be a deliberate change to this test.
	want := map[string]bool{"ID": true, "Detector": true, "Category": true, "Preview": true, "Placeholder": true}
	typ := reflect.TypeOf(Finding{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.Type.Kind() == reflect.String && !want[f.Name] {
			t.Errorf("unexpected string field %s on Finding", f.Name)
		}
		if f.Type.Kind() == reflect.Slice {
			t.Errorf("unexpected slice field %s on Finding", f.Name)
		}
	}
}
