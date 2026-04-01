package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/SharokhAtaie/ssfinder/analysis"
)

func TestPrintResult(t *testing.T) {
	result := &analysis.Result{
		Target: "test.js",
		Sources: []analysis.Source{
			{Name: "URLSearchParams", Line: 1, Category: "URL", Snippet: "const params = new URLSearchParams();"},
		},
		Sinks: []analysis.Sink{
			{Name: "innerHTML =", Line: 2, Category: "DOM", Snippet: "elem.innerHTML = x;"},
		},
	}

	var buf bytes.Buffer
	PrintResult(&buf, result)

	output := buf.String()
	
	if !strings.Contains(output, "test.js") {
		t.Error("output should contain target name")
	}
	
	if !strings.Contains(output, "Sources") {
		t.Error("output should contain Sources section")
	}
	
	if !strings.Contains(output, "Sinks") {
		t.Error("output should contain Sinks section")
	}
	
	if !strings.Contains(output, "URLSearchParams") {
		t.Error("output should contain source name")
	}
	
	if !strings.Contains(output, "innerHTML") {
		t.Error("output should contain sink name")
	}
}

func TestPrintResultJSON(t *testing.T) {
	result := &analysis.Result{
		Target:    "test.js",
		Timestamp: "2024-01-01T00:00:00Z",
		Sources: []analysis.Source{
			{Name: "URLSearchParams", Line: 1, Category: "URL", Description: "URL params"},
		},
		Sinks: []analysis.Sink{
			{Name: "innerHTML =", Line: 2, Category: "DOM", Description: "innerHTML assignment"},
		},
	}

	var buf bytes.Buffer
	PrintResultJSON(&buf, result)

	output := buf.String()
	
	if !strings.Contains(output, "test.js") {
		t.Error("JSON should contain target")
	}
	
	if !strings.Contains(output, "URLSearchParams") {
		t.Error("JSON should contain source name")
	}
	
	if !strings.Contains(output, "innerHTML") {
		t.Error("JSON should contain sink name")
	}
	
	if !strings.Contains(output, `"line"`) {
		t.Error("JSON should contain line field")
	}
}

func TestPrintResultsJSON(t *testing.T) {
	results := []*analysis.Result{
		{
			Target:    "test1.js",
			Timestamp: "2024-01-01T00:00:00Z",
			Sources:   []analysis.Source{{Name: "URLSearchParams", Line: 1, Category: "URL"}},
			Sinks:     []analysis.Sink{{Name: "innerHTML =", Line: 2, Category: "DOM"}},
		},
		{
			Target:    "test2.js",
			Timestamp: "2024-01-01T00:00:00Z",
			Sources:   []analysis.Source{{Name: "localStorage.getItem", Line: 5, Category: "Storage"}},
			Sinks:     []analysis.Sink{},
		},
	}

	var buf bytes.Buffer
	PrintResultsJSON(&buf, results)

	output := buf.String()
	
	if !strings.Contains(output, `"metadata"`) {
		t.Error("JSON should contain metadata")
	}
	
	if !strings.Contains(output, `"total_results"`) {
		t.Error("JSON should contain total_results in metadata")
	}
	
	if !strings.Contains(output, `"results"`) {
		t.Error("JSON should contain results array")
	}
	
	if !strings.Contains(output, "test1.js") {
		t.Error("JSON should contain first target")
	}
	
	if !strings.Contains(output, "test2.js") {
		t.Error("JSON should contain second target")
	}
}

func TestTrim(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		max      int
		expected string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"too long", "hello world", 5, "hello…"},
		{"with spaces", "  trimmed  ", 20, "trimmed"},
		{"empty", "", 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := trim(tt.input, tt.max)
			if result != tt.expected {
				t.Errorf("trim(%q, %d) = %q, want %q", tt.input, tt.max, result, tt.expected)
			}
		})
	}
}

func TestSinkCategoryOrder(t *testing.T) {
	// Verify Navigation comes first
	if order, ok := sinkCategoryOrder["Navigation"]; !ok || order != 0 {
		t.Error("Navigation should have highest priority (order 0)")
	}
	
	// Verify other categories exist
	expectedCategories := []string{"Execution", "DOM", "React", "Vue", "Angular", "jQuery"}
	for _, cat := range expectedCategories {
		if _, ok := sinkCategoryOrder[cat]; !ok {
			t.Errorf("missing category: %s", cat)
		}
	}
}

func TestSourceCategoryOrder(t *testing.T) {
	// Verify URL comes first
	if order, ok := sourceCategoryOrder["URL"]; !ok || order != 0 {
		t.Error("URL should have highest priority (order 0)")
	}
	
	// Verify other categories exist
	expectedCategories := []string{"React", "Router", "Svelte", "Message", "Storage"}
	for _, cat := range expectedCategories {
		if _, ok := sourceCategoryOrder[cat]; !ok {
			t.Errorf("missing category: %s", cat)
		}
	}
}
