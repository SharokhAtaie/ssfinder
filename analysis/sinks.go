package analysis

import "regexp"

// Sink represents a dangerous DOM XSS sink.
type Sink struct {
	Name        string
	Pattern     string `json:"-"`
	Description string
	Category    string
	Line        int
	Snippet     string
}

// SinkDefinitions define dangerous sinks for DOM XSS.
// Only directly exploitable sinks are included to minimize false positives.
var SinkDefinitions = []struct {
	Name        string
	Pattern     string
	Description string
	Category    string
}{
	// Navigation / URL Redirection (CRITICAL)
	{"location.href =", `(?:window\.)?location\.href\s*=[^=]`, "URL redirect", "Navigation"},
	{"location.replace", `(?:window\.)?location\.replace\s*\(`, "URL replace", "Navigation"},
	{"location.assign", `(?:window\.)?location\.assign\s*\(`, "URL assign", "Navigation"},
	{"window.open", `window\.open\s*\(`, "Window open", "Navigation"},
	{"document.location =", `document\.location\s*=[^=]`, "Document location assignment", "Navigation"},
	{"document.location.href =", `document\.location\.href\s*=[^=]`, "Document location href", "Navigation"},
	{"document.location.replace", `document\.location\.replace\s*\(`, "Document location replace", "Navigation"},
	{"document.location.assign", `document\.location\.assign\s*\(`, "Document location assign", "Navigation"},

	// DOM HTML Injection (HIGH - direct XSS)
	{"document.write", `document\.write\s*\(`, "document.write", "DOM"},
	{"document.writeln", `document\.writeln\s*\(`, "document.writeln", "DOM"},
	{"insertAdjacentHTML", `\.insertAdjacentHTML\s*\(`, "insertAdjacentHTML", "DOM"},

	// React (MEDIUM)
	{"dangerouslySetInnerHTML", `dangerouslySetInnerHTML\s*=\s*\{`, "dangerouslySetInnerHTML usage", "React"},

	// Vue (MEDIUM)
	{"v-html", `v-html\s*=`, "v-html directive", "Vue"},

	// Angular (MEDIUM)
	{"bypassSecurityTrustHtml", `bypassSecurityTrustHtml\s*\(`, "bypassSecurityTrustHtml", "Angular"},
	{"bypassSecurityTrustScript", `bypassSecurityTrustScript\s*\(`, "bypassSecurityTrustScript", "Angular"},
	{"bypassSecurityTrustUrl", `bypassSecurityTrustUrl\s*\(`, "bypassSecurityTrustUrl", "Angular"},
	{"bypassSecurityTrustResourceUrl", `bypassSecurityTrustResourceUrl\s*\(`, "bypassSecurityTrustResourceUrl", "Angular"},

	// jQuery (MEDIUM)
	{"jQuery.html()", `\$\([^)]+\)\.html\s*\(`, "jQuery .html()", "jQuery"},
	{"jQuery.append()", `\$\([^)]+\)\.append\s*\(`, "jQuery .append()", "jQuery"},
	{"jQuery.prepend()", `\$\([^)]+\)\.prepend\s*\(`, "jQuery .prepend()", "jQuery"},
	{"jQuery.after()", `\$\([^)]+\)\.after\s*\(`, "jQuery .after()", "jQuery"},
	{"jQuery.before()", `\$\([^)]+\)\.before\s*\(`, "jQuery .before()", "jQuery"},
	{"jQuery.replaceWith()", `\$\([^)]+\)\.replaceWith\s*\(`, "jQuery .replaceWith()", "jQuery"},
	{"$.parseHTML", `\$\.parseHTML\s*\(`, "$.parseHTML()", "jQuery"},
}

// compiledSinkRegexps holds pre-compiled regex patterns for performance.
var compiledSinkRegexps []*regexp.Regexp

// init compiles all sink regex patterns once at package initialization.
func init() {
	compiledSinkRegexps = make([]*regexp.Regexp, len(SinkDefinitions))
	for i, d := range SinkDefinitions {
		compiledSinkRegexps[i] = regexp.MustCompile(d.Pattern)
	}
}

// FindSinks returns all sink occurrences. Line numbers are computed from character offset.
func FindSinks(code string) []Sink {
	var out []Sink
	for i, re := range compiledSinkRegexps {
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


