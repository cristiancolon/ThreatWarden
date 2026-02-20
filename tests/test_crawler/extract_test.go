package test_crawler

import (
	"strings"
	"testing"

	"github.com/threatwarden/crawler/pipeline"
)

// -- Sample data ---------------------------------------------------------------

var sampleHTML = []byte(`<html><body>
  <script>var x = 1;</script>
  <style>.a { color: red; }</style>
  <nav>Menu</nav>
  <main><p>CVE-2025-1234 allows remote code execution via crafted input.</p></main>
  <footer>Copyright</footer>
</body></html>`)

// -- ExtractText ---------------------------------------------------------------

func TestExtract_StripsScriptAndStyle(t *testing.T) {
	text := pipeline.ExtractText(sampleHTML)
	if strings.Contains(text, "var x") {
		t.Error("script content not stripped")
	}
	if strings.Contains(text, "color: red") {
		t.Error("style content not stripped")
	}
}

func TestExtract_StripsNavHeaderFooter(t *testing.T) {
	text := pipeline.ExtractText(sampleHTML)
	if strings.Contains(text, "Menu") {
		t.Error("nav content not stripped")
	}
	if strings.Contains(text, "Copyright") {
		t.Error("footer content not stripped")
	}
}

func TestExtract_PreservesMainContent(t *testing.T) {
	text := pipeline.ExtractText(sampleHTML)
	if !strings.Contains(text, "CVE-2025-1234") {
		t.Error("main content missing")
	}
	if !strings.Contains(text, "remote code execution") {
		t.Error("advisory text missing")
	}
}

func TestExtract_TruncatesLongContent(t *testing.T) {
	long := "<html><body><p>" + strings.Repeat("a ", 60000) + "</p></body></html>"
	text := pipeline.ExtractText([]byte(long))
	if len(text) > pipeline.MaxExtractLen {
		t.Errorf("text length %d exceeds max %d", len(text), pipeline.MaxExtractLen)
	}
}

func TestExtract_EdgeCases(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		empty bool
	}{
		{"empty body", []byte("<html><body></body></html>"), true},
		{"only script", []byte("<html><body><script>alert(1)</script></body></html>"), true},
		{"plain text", []byte("<html><body>hello world</body></html>"), false},
		{"no body tag", []byte("<p>hello</p>"), false},
		{"nil input", nil, true},
		{"empty bytes", []byte{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pipeline.ExtractText(tc.input)
			if tc.empty && got != "" {
				t.Errorf("expected empty, got %q", got)
			}
			if !tc.empty && got == "" {
				t.Error("expected non-empty, got empty")
			}
		})
	}
}
