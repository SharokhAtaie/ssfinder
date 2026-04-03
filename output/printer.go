// Package output formats and prints analysis results.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/SharokhAtaie/ssfinder/analysis"
)

// ANSI colors
const (
	Reset  = "\033[0m"
	Bold   = "\033[1m"
	Dim    = "\033[2m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
)

// sinkCategoryOrder: Critical/High severity first, then Medium, then Low
var sinkCategoryOrder = map[string]int{
	"Navigation": 0, "Execution": 1, "DOM": 2,
	"React": 3, "Vue": 4, "Angular": 5, "jQuery": 6,
}

func sinkLabel(cat string) string {
	// Critical severity - Red (Navigation, Execution)
	if cat == "Navigation" || cat == "Execution" {
		return "\033[31m[" + cat + "]" + Reset
	}
	// High severity - Yellow (DOM, WebComponents)
	if cat == "DOM" || cat == "WebComponents" {
		return Yellow + "[" + cat + "]" + Reset
	}
	// Medium/Low - Dim
	return Dim + "[" + cat + "]" + Reset
}

// sourceCategoryOrder: URL and frameworks first, then Storage, then others
var sourceCategoryOrder = map[string]int{
	"URL": 0, "React": 1, "Router": 2, "Svelte": 3, "Message": 4, "Storage": 5,
}

// sourceLabel: URL, React, Router, Svelte, Message = more important (yellow); Storage = dim
func sourceLabel(cat string) string {
	if cat == "Storage" {
		return Dim + "[" + cat + "]" + Reset
	}
	return Yellow + "[" + cat + "]" + Reset
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
		sinks := make([]analysis.Sink, len(r.Sinks))
		copy(sinks, r.Sinks)
		sort.Slice(sinks, func(i, j int) bool {
			oi, ok1 := sinkCategoryOrder[sinks[i].Category]
			oj, ok2 := sinkCategoryOrder[sinks[j].Category]
			if !ok1 {
				oi = 99
			}
			if !ok2 {
				oj = 99
			}
			return oi < oj
		})
		for _, s := range sinks {
			fmt.Fprintf(w, "  %s Line %-5d | %s | %s\n", sinkLabel(s.Category), s.Line, s.Name, trim(s.Snippet, 60))
		}
		fmt.Fprintln(w)
	}

	if srcCount > 0 {
		fmt.Fprintf(w, "%s%s%s\n", Bold, "▸ Sources", Reset)
		fmt.Fprintln(w, strings.Repeat("─", 72))
		sources := make([]analysis.Source, len(r.Sources))
		copy(sources, r.Sources)
		sort.Slice(sources, func(i, j int) bool {
			oi, ok1 := sourceCategoryOrder[sources[i].Category]
			oj, ok2 := sourceCategoryOrder[sources[j].Category]
			if !ok1 {
				oi = 99
			}
			if !ok2 {
				oj = 99
			}
			return oi < oj
		})
		for _, s := range sources {
			fmt.Fprintf(w, "  %s Line %-5d | %s | %s\n", sourceLabel(s.Category), s.Line, s.Name, trim(s.Snippet, 60))
		}
		fmt.Fprintln(w)
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

// PrintResultJSON prints the result as JSON to w with metadata.
func PrintResultJSON(w io.Writer, r *analysis.Result) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resultToJSON(r))
}

// PrintResultsJSON prints multiple results as a JSON object with metadata.
func PrintResultsJSON(w io.Writer, results []*analysis.Result) {
	type metadata struct {
		TotalResults int    `json:"total_results"`
		TotalSources int    `json:"total_sources"`
		TotalSinks   int    `json:"total_sinks"`
		Timestamp    string `json:"timestamp"`
		Tool         string `json:"tool"`
		Version      string `json:"version"`
	}
	
	totalSources := 0
	totalSinks := 0
	var firstTimestamp string
	if len(results) > 0 {
		firstTimestamp = results[0].Timestamp
	}
	
	for _, r := range results {
		totalSources += len(r.Sources)
		totalSinks += len(r.Sinks)
	}
	
	meta := metadata{
		TotalResults: len(results),
		TotalSources: totalSources,
		TotalSinks:   totalSinks,
		Timestamp:    firstTimestamp,
		Tool:         "SSFinder",
		Version:      "1.0.0",
	}
	
	output := map[string]interface{}{
		"metadata": meta,
		"results":  results,
	}
	
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(output)
}

func resultToJSON(r *analysis.Result) interface{} {
	type jSource struct {
		Name     string `json:"name"`
		Line     int    `json:"line"`
		Category string `json:"category"`
		Desc     string `json:"description"`
		Code     string `json:"code"`
	}
	type jSink struct {
		Name     string `json:"name"`
		Line     int    `json:"line"`
		Category string `json:"category"`
		Desc     string `json:"description"`
		Code     string `json:"code"`
	}
	out := struct {
		Target   string    `json:"target"`
		Sources  []jSource `json:"sources"`
		Sinks    []jSink   `json:"sinks"`
	}{
		Target:   r.Target,
	}
	for _, s := range r.Sources {
		out.Sources = append(out.Sources, jSource{Name: s.Name, Line: s.Line, Category: s.Category, Desc: s.Description, Code: strings.TrimSpace(s.Snippet)})
	}
	for _, s := range r.Sinks {
		out.Sinks = append(out.Sinks, jSink{Name: s.Name, Line: s.Line, Category: s.Category, Desc: s.Description, Code: strings.TrimSpace(s.Snippet)})
	}
	return out
}
