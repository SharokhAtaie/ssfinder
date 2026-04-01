// Package analysis scans JavaScript for DOM XSS sources and sinks.
package analysis

import (
	"regexp"
	"strings"
)

// Source represents a DOM XSS source (user-controllable input).
type Source struct {
	Name        string
	Pattern     string
	Description string
	Category    string
	Line        int
	Snippet     string
}

// Predefined DOM XSS sources (user-controllable data).
// Includes browser APIs + framework-specific (React, Vue, Next.js, Angular, Svelte, SolidJS).
var SourceDefinitions = []struct {
	Name        string
	Pattern     string
	Description string
	Category    string
}{
	// Browser / URL - High Priority
	{"URLSearchParams", `(?i)(?:new\s+)?URLSearchParams\s*\(`, "URL params", "URL"},
	{"searchParams.get", `(?i)searchParams\.get\s*\(`, "Get URL param", "URL"},
	{"searchParams.getAll", `(?i)searchParams\.getAll\s*\(`, "Get all URL params", "URL"},
	
	// Storage - Medium Priority
	{"localStorage.getItem", `(?i)localStorage\.getItem\s*\(`, "LocalStorage read", "Storage"},
	{"localStorage[]", `(?i)localStorage\s*\[`, "LocalStorage bracket access", "Storage"},
	{"sessionStorage.getItem", `(?i)sessionStorage\.getItem\s*\(`, "SessionStorage read", "Storage"},
	{"sessionStorage[]", `(?i)sessionStorage\s*\[`, "SessionStorage bracket access", "Storage"},
	
	// Message / Web APIs - Medium Priority
	{"postMessage listener", `(?i)(?:window\.)?addEventListener\s*\(\s*['\"]message['\"]`, "PostMessage listener", "Message"},
	{"postMessage wildcard", `(?i)\.postMessage\s*\([^,]+,\s*['""]\*['""]`, "postMessage with wildcard origin", "Message"},
	{"MessagePort", `(?i)(?:new\s+)?MessagePort\s*\(`, "MessagePort communication", "Message"},
	
	// React / React Router - High Priority
	{"useSearchParams", `(?:\buseSearchParams\s*\(|\.useSearchParams\s*\))`, "React Router query", "React"},
	{"useParams", `(?:\buseParams\s*\(|\.useParams\s*\))`, "React Router params", "React"},
	
	// Next.js / Vue Router - High Priority
	{"router.query", `(?i)router\.query\b`, "Next.js route query", "Router"},
	{"route.query", `(?i)route\.query\b`, "Vue/React route query", "Router"},
	{"route.params", `(?i)route\.params\b`, "Vue/React route params", "Router"},
	{"$route.query", `(?i)\$route\.query\b`, "Vue route query", "Router"},
	{"$route.params", `(?i)\$route\.params\b`, "Vue route params", "Router"},
	
	// Svelte / SvelteKit - Medium Priority
	{"$page.url", `(?i)\$page\.url\b`, "SvelteKit page URL", "Svelte"},
	{"$page.params", `(?i)\$page\.params\b`, "SvelteKit page params", "Svelte"},
	{"$page.query", `(?i)\$page\.query\b`, "SvelteKit page query", "Svelte"},
}

// compiledSourceRegexps holds pre-compiled regex patterns for performance.
var compiledSourceRegexps []*regexp.Regexp

// init compiles all source regex patterns once at package initialization.
func init() {
	compiledSourceRegexps = make([]*regexp.Regexp, len(SourceDefinitions))
	for i, d := range SourceDefinitions {
		compiledSourceRegexps[i] = regexp.MustCompile(d.Pattern)
	}
}

// FindSources returns all source occurrences in code. Line numbers are computed from
// character offset (1 + newlines before match) so they match the actual file/response.
func FindSources(code string) []Source {
	var out []Source
	for i, re := range compiledSourceRegexps {
		def := SourceDefinitions[i]
		locs := re.FindAllStringIndex(code, -1)
		for _, loc := range locs {
			lineNum := lineNumber(code, loc[0])
			lineStart, lineEnd := lineBounds(code, loc[0])
			lineContent := code[lineStart:lineEnd]
			// Match may span multiple lines; ensure we don't slice with start > end
			afterStart := loc[1]
			if afterStart > lineEnd {
				afterStart = lineEnd
			}
			afterMatch := code[afterStart:lineEnd]
			if isAssignmentLHS(afterMatch) {
				continue
			}
			startInLine := loc[0] - lineStart
			endInLine := loc[1] - lineStart
			if endInLine > len(lineContent) {
				endInLine = len(lineContent)
			}
			snippet := extractSnippet(lineContent, startInLine, endInLine, 35)
			out = append(out, Source{
				Name:        def.Name,
				Pattern:     def.Pattern,
				Description: def.Description,
				Category:    def.Category,
				Line:        lineNum,
				Snippet:     snippet,
			})
		}
	}
	return out
}

func isAssignmentLHS(rest string) bool {
	rest = strings.TrimLeft(rest, " \t")
	return strings.HasPrefix(rest, "=")
}
