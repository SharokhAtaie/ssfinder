package analysis

// Result holds the full analysis result for one file/URL.
type Result struct {
	Target  string
	Sources []Source
	Sinks   []Sink
}

// Run finds all sources and sinks in code.
func Run(code, target string) *Result {
	return &Result{
		Target:  target,
		Sources: FindSources(code),
		Sinks:   FindSinks(code),
	}
}
