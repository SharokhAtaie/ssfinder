package analysis

import (
	"fmt"
)

// Result holds the full analysis result for one file/URL.
type Result struct {
	Target    string
	Sources   []Source
	Sinks     []Sink
}

// Run finds all sources and sinks in code with deduplication and risk scoring.
func Run(code, target string) *Result {
	result := &Result{
		Target:  target,
		Sources: FindSources(code),
		Sinks:   FindSinks(code),
	}
	
	// Deduplicate findings
	result.Sources = deduplicateSources(result.Sources)
	result.Sinks = deduplicateSinks(result.Sinks)
	
	return result
}

// deduplicateSources removes duplicate sources based on line+name+snippet.
func deduplicateSources(sources []Source) []Source {
	seen := make(map[string]bool)
	result := make([]Source, 0, len(sources))
	
	for _, s := range sources {
		key := fmt.Sprintf("%d:%s:%s", s.Line, s.Name, s.Snippet)
		if !seen[key] {
			seen[key] = true
			result = append(result, s)
		}
	}
	return result
}

// deduplicateSinks removes duplicate sinks based on line+name+snippet.
func deduplicateSinks(sinks []Sink) []Sink {
	seen := make(map[string]bool)
	result := make([]Sink, 0, len(sinks))
	
	for _, s := range sinks {
		key := fmt.Sprintf("%d:%s:%s", s.Line, s.Name, s.Snippet)
		if !seen[key] {
			seen[key] = true
			result = append(result, s)
		}
	}
	return result
}
