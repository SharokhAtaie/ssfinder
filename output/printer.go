package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/SharokhAtaie/ssfinder/analysis"
)

// ANSI colors
const (
	Reset   = "\033[0m"
	Bold   = "\033[1m"
	Dim    = "\033[2m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	White  = "\033[37m"
	BgRed  = "\033[41m"
	Cyan   = "\033[36m"
)

func severityBadge(s analysis.Severity) string {
	switch s {
	case analysis.Critical:
		return BgRed + White + Bold + " CRITICAL " + Reset
	case analysis.High:
		return Red + Bold + " HIGH " + Reset
	case analysis.Medium:
		return Yellow + " MEDIUM " + Reset
	case analysis.Low:
		return Dim + " LOW " + Reset
	default:
		return " INFO "
	}
}

// PrintResult prints the analysis result to w.
func PrintResult(w io.Writer, r *analysis.Result) {
	target := r.Target
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s%s%s %s\n", Bold, "▸ Target", Reset, Cyan+target+Reset)
	fmt.Fprintln(w, strings.Repeat("─", 72))

	srcCount := len(r.Sources)
	sinkCount := len(r.Sinks)
	fmt.Fprintf(w, "  %sSources%s: %s%d%s  %sSinks%s: %s%d%s\n",
		Bold, Reset, Green, srcCount, Reset,
		Bold, Reset, Yellow, sinkCount, Reset)
	fmt.Fprintln(w)

	if sinkCount > 0 {
		fmt.Fprintf(w, "%s%s%s\n", Bold, "▸ Sinks", Reset)
		fmt.Fprintln(w, strings.Repeat("─", 72))
		for _, s := range r.Sinks {
			fmt.Fprintf(w, "  %s Line %-5d | %s | %s\n", severityBadge(s.Severity), s.Line, s.Name, trim(s.Snippet, 60))
		}
		fmt.Fprintln(w)
	}

	if srcCount > 0 {
		fmt.Fprintf(w, "%s%s%s\n", Bold, "▸ Sources", Reset)
		fmt.Fprintln(w, strings.Repeat("─", 72))
		for _, s := range r.Sources {
			fmt.Fprintf(w, "  %s Line %-5d | %s | %s\n", Blue+"[src]"+Reset, s.Line, s.Name, trim(s.Snippet, 60))
		}
		fmt.Fprintln(w)
	}

	if srcCount == 0 && sinkCount == 0 {
		fmt.Fprintf(w, "  %sNo sources or sinks found.%s\n", Dim, Reset)
	}
	fmt.Fprintln(w)
}

func trim(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// PrintResultJSON prints the result as JSON to w.
func PrintResultJSON(w io.Writer, r *analysis.Result) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resultToJSON(r))
}

// PrintResultsJSON prints multiple results as a JSON object with "results" array.
func PrintResultsJSON(w io.Writer, results []*analysis.Result) {
	out := make([]interface{}, 0, len(results))
	for _, r := range results {
		out = append(out, resultToJSON(r))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(map[string]interface{}{"results": out})
}

func resultToJSON(r *analysis.Result) interface{} {
	type jSource struct {
		Name string `json:"name"`
		Line int    `json:"line"`
		Desc string `json:"description"`
	}
	type jSink struct {
		Name string `json:"name"`
		Line int    `json:"line"`
		Sev  string `json:"severity"`
		Desc string `json:"description"`
	}
	out := struct {
		Target  string    `json:"target"`
		Sources []jSource `json:"sources"`
		Sinks   []jSink   `json:"sinks"`
	}{
		Target: r.Target,
	}
	for _, s := range r.Sources {
		out.Sources = append(out.Sources, jSource{Name: s.Name, Line: s.Line, Desc: s.Description})
	}
	for _, s := range r.Sinks {
		out.Sinks = append(out.Sinks, jSink{Name: s.Name, Line: s.Line, Sev: string(s.Severity), Desc: s.Description})
	}
	return out
}
