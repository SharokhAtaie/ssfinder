package analysis

import (
	"testing"
)

func TestFindSources(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		expected int
	}{
		{
			name:     "URLSearchParams source",
			code:     "const params = new URLSearchParams(window.location.search);",
			expected: 2, // Matches both URLSearchParams and location.search
		},
		{
			name:     "localStorage.getItem source",
			code:     "const data = localStorage.getItem('key');",
			expected: 1,
		},
		{
			name:     "postMessage listener",
			code:     "window.addEventListener('message', handler);",
			expected: 1,
		},
		{
			name:     "React useSearchParams",
			code:     "const [searchParams] = useSearchParams(); const id = searchParams.get('id');",
			expected: 2, // Matches both useSearchParams and searchParams.get
		},
		{
			name:     "router.query Next.js",
			code:     "const query = router.query.id;",
			expected: 1,
		},
		{
			name:     "SvelteKit $page.url",
			code:     "const url = $page.url;",
			expected: 1,
		},
		{
			name:     "multiple sources",
			code: `
				const params = new URLSearchParams();
				const data = localStorage.getItem('x');
			`,
			expected: 2,
		},
		{
			name:     "no sources",
			code:     "console.log('hello');",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sources := FindSources(tt.code)
			if len(sources) != tt.expected {
				t.Errorf("expected %d sources, got %d", tt.expected, len(sources))
			}
		})
	}
}

func TestFindSinks(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		expected int
	}{
		{
			name:     "innerHTML sink",
			code:     "element.innerHTML = userInput;",
			expected: 1,
		},
		{
			name:     "location.href redirect",
			code:     "window.location.href = 'http://evil.com';",
			expected: 1,
		},
		{
			name:     "document.write sink",
			code:     "document.write('<script>alert(1)</script>');",
			expected: 1,
		},
		{
			name:     "dangerouslySetInnerHTML React",
			code:     "<div dangerouslySetInnerHTML={{__html: content}} />",
			expected: 1,
		},
		{
			name:     "window.open navigation",
			code:     "window.open(url, '_blank');",
			expected: 1,
		},
		{
			name:     "eval execution",
			code:     "eval(userInput);",
			expected: 1,
		},
		{
			name:     "jQuery html sink",
			code:     "$('#elem').html(userInput);",
			expected: 1,
		},
		{
			name:     "multiple sinks",
			code: `
				elem.innerHTML = x;
				location.href = y;
				document.write(z);
			`,
			expected: 3,
		},
		{
			name:     "no sinks",
			code:     "console.log('safe');",
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sinks := FindSinks(tt.code)
			if len(sinks) != tt.expected {
				t.Errorf("expected %d sinks, got %d", tt.expected, len(sinks))
			}
		})
	}
}

func TestLineNumber(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		offset   int
		expected int
	}{
		{
			name:     "first line",
			code:     "var x = 1;",
			offset:   5,
			expected: 1,
		},
		{
			name:     "second line",
			code:     "var x = 1;\nvar y = 2;",
			offset:   15,
			expected: 2,
		},
		{
			name:     "third line",
			code:     "line1\nline2\nline3",
			offset:   12,
			expected: 3,
		},
		{
			name:     "offset at start",
			code:     "test",
			offset:   0,
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := lineNumber(tt.code, tt.offset)
			if line != tt.expected {
				t.Errorf("expected line %d, got %d", tt.expected, line)
			}
		})
	}
}

func TestExtractSnippet(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		start    int
		end      int
		context  int
		expected string
	}{
		{
			name:     "with context",
			line:     "var x = location.hash;",
			start:    8,
			end:      21,
			context:  3,
			expected: "= location.hash;",
		},
		{
			name:     "limited context left",
			line:     "var x = location.hash;",
			start:    0,
			end:      5,
			context:  3,
			expected: "var x =",
		},
		{
			name:     "limited context right",
			line:     "var x = 1;",
			start:    5,
			end:      10,
			context:  5,
			expected: "var x = 1;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			snippet := extractSnippet(tt.line, tt.start, tt.end, tt.context)
			if snippet != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, snippet)
			}
		})
	}
}

func TestDeduplication(t *testing.T) {
	t.Run("duplicate sources", func(t *testing.T) {
		sources := []Source{
			{Name: "URLSearchParams", Line: 1, Snippet: "const params = new URLSearchParams();"},
			{Name: "URLSearchParams", Line: 1, Snippet: "const params = new URLSearchParams();"},
			{Name: "localStorage.getItem", Line: 2, Snippet: "localStorage.getItem('x');"},
		}
		
		deduped := deduplicateSources(sources)
		if len(deduped) != 2 {
			t.Errorf("expected 2 unique sources, got %d", len(deduped))
		}
	})

	t.Run("duplicate sinks", func(t *testing.T) {
		sinks := []Sink{
			{Name: "innerHTML =", Line: 1, Snippet: "elem.innerHTML = x;"},
			{Name: "innerHTML =", Line: 1, Snippet: "elem.innerHTML = x;"},
			{Name: "location.href =", Line: 2, Snippet: "location.href = y;"},
		}
		
		deduped := deduplicateSinks(sinks)
		if len(deduped) != 2 {
			t.Errorf("expected 2 unique sinks, got %d", len(deduped))
		}
	})
}

func TestRun(t *testing.T) {
	code := `
		const params = new URLSearchParams();
		element.innerHTML = userInput;
		window.location.href = url;
	`
	
	result := Run(code, "test.js")
	
	if result.Target != "test.js" {
		t.Errorf("expected target 'test.js', got '%s'", result.Target)
	}
	
	if len(result.Sources) == 0 {
		t.Error("expected sources to be found")
	}
	
	if len(result.Sinks) == 0 {
		t.Error("expected sinks to be found")
	}
}

func TestIsAssignmentLHS(t *testing.T) {
	tests := []struct {
		name     string
		rest     string
		expected bool
	}{
		{"assignment", "= value", true},
		{"assignment with space", "  = value", true},
		{"not assignment", "value", false},
		{"empty", "", false},
		{"plus equals", "+= value", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAssignmentLHS(tt.rest)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}
