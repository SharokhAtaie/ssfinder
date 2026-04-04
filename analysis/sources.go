// Package analysis scans JavaScript for DOM XSS sources and sinks.
package analysis

import (
	"regexp"
	"strings"
)

// Source represents a DOM XSS source (user-controllable input).
type Source struct {
	Name        string
	Pattern     string `json:"-"`
	Description string
	Category    string
	Line        int
	Snippet     string
}

// Predefined DOM XSS sources (user-controllable data).
// Only attacker-controllable inputs that can directly reach sinks.
var SourceDefinitions = []struct {
	Name        string
	Pattern     string
	Description string
	Category    string
}{
	// Browser URL properties - directly attacker-controlled
	{"URLSearchParams", `(?:new\s+)?URLSearchParams\s*\(`, "URL params", "URL"},
	{"searchParams.get", `searchParams\.get\s*\(`, "Get URL param", "URL"},
	{"searchParams.getAll", `searchParams\.getAll\s*\(`, "Get all URL params", "URL"},

	// Message - attacker can send cross-origin messages
	{"postMessage listener", `(?:window\.)?addEventListener\s*\(\s*['"]message['"]`, "PostMessage listener", "Message"},
	{"postMessage wildcard", `\.postMessage\s*\([^,]+,\s*['"]\*['"]`, "postMessage with wildcard origin", "Message"},
	{"MessageChannel", `new\s+MessageChannel\s*\(`, "MessageChannel creation", "Message"},
	{"port.onmessage", `\.onmessage\s*=`, "Port message handler", "Message"},

	// React / React Router
	{"useSearchParams", `\buseSearchParams\s*\(`, "React Router query", "React"},
	{"useParams", `\buseParams\s*\(`, "React Router params", "React"},

	// Next.js / Vue Router
	{"router.query", `router\.query\b`, "Next.js route query", "Router"},
	{"route.query", `route\.query\b`, "Vue/React route query", "Router"},
	{"route.params", `route\.params\b`, "Vue/React route params", "Router"},
	{"$route.query", `\$route\.query\b`, "Vue route query", "Router"},
	{"$route.params", `\$route\.params\b`, "Vue route params", "Router"},

	// Svelte / SvelteKit
	{"$page.url", `\$page\.url\b`, "SvelteKit page URL", "Svelte"},
	{"$page.params", `\$page\.params\b`, "SvelteKit page params", "Svelte"},
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
