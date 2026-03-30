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
// Includes browser APIs + framework-specific (React, Vue, Next.js, Angular).
var SourceDefinitions = []struct {
	Name        string
	Pattern     string
	Description string
	Category    string
}{
	// Browser / URL
	{"location.hash", `(?i)(?:window\.)?location\.hash\b`, "Fragment (read)", "URL"},
	{"URLSearchParams", `(?i)(?:new\s+)?URLSearchParams\s*\(`, "URL params", "URL"},
	{"searchParams.get", `(?i)searchParams\.get\s*\(`, "Get URL param", "URL"},
	// Storage
	{"localStorage", `(?i)localStorage\.getItem\s*\(|(?i)localStorage\s*\[`, "LocalStorage", "Storage"},
	{"sessionStorage", `(?i)sessionStorage\.getItem\s*\(|(?i)sessionStorage\s*\[`, "SessionStorage", "Storage"},
	// Message
	{"postMessage", `(?i)(?:window\.)?addEventListener\s*\(\s*['\"]message['\"]`, "PostMessage listener", "Message"},
	// React / React Query / TanStack (matches both useHook() and minified (0, x.useHook)())
	{"useSearchParams", `(?:\buseSearchParams\s*\(|\.useSearchParams\s*\))`, "React Router query string", "React"},
	{"useParams", `(?:\buseParams\s*\(|\.useParams\s*\))`, "React Router path params", "React"},
	// Next.js / Vue Router
	{"router.query", `(?i)router\.query\b`, "Next.js route query", "Router"},
	{"route.query", `(?i)route\.query\b`, "Vue/React route query", "Router"},
	{"route.params", `(?i)route\.params\b`, "Vue/React route params", "Router"},
}

// FindSources returns all source occurrences in code. Line numbers are computed from
// character offset (1 + newlines before match) so they match the actual file/response.
func FindSources(code string) []Source {
	var out []Source
	for i, re := range buildSourceRegexps() {
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

func buildSourceRegexps() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(SourceDefinitions))
	for i, d := range SourceDefinitions {
		out[i] = regexp.MustCompile(d.Pattern)
	}
	return out
}
