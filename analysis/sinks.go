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
// Category: Navigation = Critical; DOM/SVG = High; React/Vue/Angular/jQuery = Medium; Other = Low
var SinkDefinitions = []struct {
	Name        string
	Pattern     string
	Description string
	Category    string
}{
	// Navigation / URL Redirection (CRITICAL - can lead to phishing, credential theft)
	{"location.href =", `(?i)(?:window\.)?location\.href\s*=`, "URL redirect", "Navigation"},
	{"location.replace", `(?i)(?:window\.)?location\.replace\s*\(`, "URL replace", "Navigation"},
	{"location.assign", `(?i)(?:window\.)?location\.assign\s*\(`, "URL assign", "Navigation"},
	{"window.open", `(?i)window\.open\s*\(`, "Window open", "Navigation"},
	{"document.location =", `(?i)document\.location\s*=`, "Document location assignment", "Navigation"},
	{"document.location.href =", `(?i)document\.location\.href\s*=`, "Document location href", "Navigation"},
	{"document.location.replace", `(?i)document\.location\.replace\s*\(`, "Document location replace", "Navigation"},
	{"document.location.assign", `(?i)document\.location\.assign\s*\(`, "Document location assign", "Navigation"},
	
	// DOM HTML Injection (HIGH - direct XSS)
	{"innerHTML =", `(?i)\.innerHTML\s*=[^=]`, "innerHTML assignment", "DOM"},
	{"innerHTML +=", `(?i)\.innerHTML\s*\+\=`, "innerHTML append", "DOM"},
	{"outerHTML =", `(?i)\.outerHTML\s*=[^=]`, "outerHTML assignment", "DOM"},
	{"document.write", `(?i)document\.write\s*\(`, "document.write", "DOM"},
	{"document.writeln", `(?i)document\.writeln\s*\(`, "document.writeln", "DOM"},
	{"document.open", `(?i)document\.open\s*\(`, "document.open", "DOM"},
	
	// DOM Insertion Methods (HIGH - can inject HTML)
	{"insertAdjacentHTML", `(?i)\.insertAdjacentHTML\s*\(`, "insertAdjacentHTML", "DOM"},
	{"createContextualFragment", `(?i)createContextualFragment\s*\(`, "createContextualFragment", "DOM"},
	
	// Script Injection (CRITICAL)
	{"eval", `(?i)\beval\s*\(`, "eval() execution", "Execution"},
	{"setTimeout string", `(?i)setTimeout\s*\(\s*["']`, "setTimeout with string", "Execution"},
	{"setInterval string", `(?i)setInterval\s*\(\s*["']`, "setInterval with string", "Execution"},
	{"execScript", `(?i)execScript\s*\(`, "execScript", "Execution"},
	
	// React (MEDIUM - framework-level XSS)
	{"dangerouslySetInnerHTML", `(?i)dangerouslySetInnerHTML\b`, "dangerouslySetInnerHTML", "React"},
	{"__html", `\b__html\s*:`, "__html property", "React"},
	
	// Vue (MEDIUM)
	{"v-html", `(?i)v-html\s*[=:]`, "v-html directive", "Vue"},
	
	// Angular (MEDIUM)
	{"bypassSecurityTrustHtml", `(?i)bypassSecurityTrustHtml\s*\(`, "bypassSecurityTrustHtml", "Angular"},
	{"bypassSecurityTrustScript", `(?i)bypassSecurityTrustScript\s*\(`, "bypassSecurityTrustScript", "Angular"},
	{"bypassSecurityTrustStyle", `(?i)bypassSecurityTrustStyle\s*\(`, "bypassSecurityTrustStyle", "Angular"},
	{"bypassSecurityTrustUrl", `(?i)bypassSecurityTrustUrl\s*\(`, "bypassSecurityTrustUrl", "Angular"},
	{"bypassSecurityTrustResourceUrl", `(?i)bypassSecurityTrustResourceUrl\s*\(`, "bypassSecurityTrustResourceUrl", "Angular"},
	
	// jQuery (MEDIUM)
	{"jQuery.html()", `(?i)\$\([^)]+\)\.html\s*\(`, "jQuery .html()", "jQuery"},
	{"$.html()", `(?i)\$\.html\s*\(`, "$.html()", "jQuery"},
	{"jQuery.append()", `(?i)\$\([^)]+\)\.append\s*\(`, "jQuery .append()", "jQuery"},
	{"jQuery.prepend()", `(?i)\$\([^)]+\)\.prepend\s*\(`, "jQuery .prepend()", "jQuery"},
	{"jQuery.after()", `(?i)\$\([^)]+\)\.after\s*\(`, "jQuery .after()", "jQuery"},
	{"jQuery.before()", `(?i)\$\([^)]+\)\.before\s*\(`, "jQuery .before()", "jQuery"},
	{"jQuery.replaceWith()", `(?i)\$\([^)]+\)\.replaceWith\s*\(`, "jQuery .replaceWith()", "jQuery"},
	{"jQuery.wrap()", `(?i)\$\([^)]+\)\.wrap\s*\(`, "jQuery .wrap()", "jQuery"},
	{"jQuery.wrapAll()", `(?i)\$\([^)]+\)\.wrapAll\s*\(`, "jQuery .wrapAll()", "jQuery"},
	{"$.parseHTML", `(?i)\$\.parseHTML\s*\(`, "$.parseHTML()", "jQuery"},
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


