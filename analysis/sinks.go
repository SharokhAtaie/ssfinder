package analysis

import "regexp"

// Severity of a sink for DOM XSS.
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
)

// Sink represents a dangerous DOM XSS sink.
type Sink struct {
	Name        string
	Pattern     string
	Description string
	Category    string
	Severity    Severity
	Line        int
	Snippet     string
}

// SinkDefinitions define dangerous sinks for DOM XSS.
var SinkDefinitions = []struct {
	Name        string
	Pattern     string
	Description string
	Category    string
	Severity    Severity
}{
	{"eval", `(?i)\beval\s*\(`, "Code execution", "Execution", Critical},
	{"innerHTML", `(?i)\.innerHTML\s*[\+\=]`, "HTML injection", "DOM", Critical},
	{"outerHTML", `(?i)\.outerHTML\s*[\+\=]`, "HTML injection", "DOM", Critical},
	{"document.write", `(?i)document\.write\s*\(`, "HTML injection", "DOM", Critical},
	{"document.writeln", `(?i)document\.writeln\s*\(`, "HTML injection", "DOM", Critical},
	{"insertAdjacentHTML", `(?i)\.insertAdjacentHTML\s*\(`, "HTML injection", "DOM", Critical},
	{"createContextualFragment", `(?i)Range\.createContextualFragment\s*\(`, "HTML fragment", "DOM", Critical},
	{"jQuery.html", `(?i)\$\([^)]+\)\.html\s*\(`, "jQuery HTML", "DOM", Critical},
	{"$.html", `(?i)\$\.html\s*\(`, "jQuery HTML", "DOM", Critical},
	{"location.href =", `(?i)(?:window\.)?location\.href\s*=`, "Redirect", "Navigation", High},
	{"location =", `(?i)(?:window\.)?location\s*=`, "Redirect", "Navigation", High},
	{"location.replace", `(?i)(?:window\.)?location\.replace\s*\(`, "Redirect", "Navigation", High},
	{"location.assign", `(?i)(?:window\.)?location\.assign\s*\(`, "Redirect", "Navigation", High},
	{"window.open", `(?i)window\.open\s*\(`, "New window", "Navigation", High},
	{"document.location", `(?i)document\.location\s*[\=\.]`, "Document location", "Navigation", High},
	{"script.src", `(?i)(?:script|element)\.src\s*=`, "Script source", "Resource", High},
	{"script.text", `(?i)script\.(?:text|textContent|innerText)\s*=`, "Script content", "Resource", High},
	{"iframe.srcdoc", `(?i)\.srcdoc\s*=`, "iframe content", "Resource", High},
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
				Severity:    def.Severity,
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
