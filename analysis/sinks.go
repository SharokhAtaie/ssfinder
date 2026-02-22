package analysis

import "regexp"

// Sink represents a dangerous DOM XSS sink.
type Sink struct {
	Name        string
	Pattern     string
	Description string
	Category    string
	Line        int
	Snippet     string
}

// SinkDefinitions define dangerous sinks for DOM XSS.
// Category: Navigation = more sensitive; DOM/React/Vue/Angular/jQuery = less important.
var SinkDefinitions = []struct {
	Name        string
	Pattern     string
	Description string
	Category    string
}{
	// DOM HTML injection (less important)
	{"innerHTML", `(?i)\.innerHTML\s*[\+\=]`, "HTML injection", "DOM"},
	{"outerHTML", `(?i)\.outerHTML\s*[\+\=]`, "HTML injection", "DOM"},
	{"document.write", `(?i)document\.write\s*\(`, "HTML injection", "DOM"},
	{"document.writeln", `(?i)document\.writeln\s*\(`, "HTML injection", "DOM"},
	{"insertAdjacentHTML", `(?i)\.insertAdjacentHTML\s*\(`, "HTML injection", "DOM"},
	{"createContextualFragment", `(?i)Range\.createContextualFragment\s*\(`, "HTML fragment", "DOM"},
	// React (less important)
	{"dangerouslySetInnerHTML", `(?i)dangerouslySetInnerHTML\b`, "React raw HTML", "React"},
	{"__html", `\b__html\s*:`, "React dangerouslySetInnerHTML value", "React"},
	// Vue (less important)
	{"v-html", `(?i)v-html\s*[=:]`, "Vue raw HTML directive", "Vue"},
	// Angular (less important)
	{"bypassSecurityTrustHtml", `(?i)bypassSecurityTrustHtml\s*\(`, "Angular disable sanitization", "Angular"},
	{"bypassSecurityTrustUrl", `(?i)bypassSecurityTrustUrl\s*\(`, "Angular bypass URL", "Angular"},
	{"bypassSecurityTrustResourceUrl", `(?i)bypassSecurityTrustResourceUrl\s*\(`, "Angular bypass resource URL", "Angular"},
	// jQuery (less important)
	{"jQuery.html", `(?i)\$\([^)]+\)\.html\s*\(`, "jQuery HTML", "jQuery"},
	{"$.html", `(?i)\$\.html\s*\(`, "jQuery HTML", "jQuery"},
	{"jQuery.append", `(?i)\$\([^)]+\)\.append\s*\(`, "jQuery append HTML", "jQuery"},
	{"jQuery.prepend", `(?i)\$\([^)]+\)\.prepend\s*\(`, "jQuery prepend HTML", "jQuery"},
	// Navigation / URL (more sensitive)
	{"location.href =", `(?i)(?:window\.)?location\.href\s*=`, "Redirect", "Navigation"},
	{"location =", `(?i)(?:window\.)?\blocation\b\s*=`, "Redirect", "Navigation"},
	{"location.replace", `(?i)(?:window\.)?location\.replace\s*\(`, "Redirect", "Navigation"},
	{"location.assign", `(?i)(?:window\.)?location\.assign\s*\(`, "Redirect", "Navigation"},
	{"window.open", `(?i)window\.open\s*\(`, "New window", "Navigation"},
	{"document.location", `(?i)document\.location\s*[\=\.]`, "Document location", "Navigation"},
}

// FindSinks returns all sink occurrences. Line numbers are computed from character offset.
func FindSinks(code string) []Sink {
	var out []Sink
	for i, re := range buildSinkRegexps() {
		def := SinkDefinitions[i]
		locs := re.FindAllStringIndex(code, -1)
		for _, loc := range locs {
			lineNum := lineNumber(code, loc[0])
			lineStart, lineEnd := lineBounds(code, loc[0])
			lineContent := code[lineStart:lineEnd]
			startInLine := loc[0] - lineStart
			endInLine := loc[1] - lineStart
			if endInLine > len(lineContent) {
				endInLine = len(lineContent)
			}
			snippet := extractSnippet(lineContent, startInLine, endInLine, 35)
			out = append(out, Sink{
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

func buildSinkRegexps() []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(SinkDefinitions))
	for i, d := range SinkDefinitions {
		out[i] = regexp.MustCompile(d.Pattern)
	}
	return out
}
