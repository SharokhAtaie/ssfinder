package analysis

import "strings"

// lineNumber returns 1-based line number for the given byte offset in code.
func lineNumber(code string, offset int) int {
	if offset <= 0 {
		return 1
	}
	if offset > len(code) {
		offset = len(code)
	}
	return 1 + strings.Count(code[:offset], "\n")
}

// lineBounds returns start and end byte offsets of the line containing offset.
func lineBounds(code string, offset int) (start, end int) {
	start = strings.LastIndex(code[:offset], "\n") + 1
	end = strings.Index(code[offset:], "\n")
	if end == -1 {
		end = len(code)
	} else {
		end = offset + end
	}
	return start, end
}

// extractSnippet returns a trimmed substring of line around [start:end] with context chars.
func extractSnippet(line string, start, end int, context int) string {
	if start > end {
		start, end = end, start
	}
	if start < 0 {
		start = 0
	}
	if end > len(line) {
		end = len(line)
	}
	s := start - context
	if s < 0 {
		s = 0
	}
	e := end + context
	if e > len(line) {
		e = len(line)
	}
	return strings.TrimSpace(line[s:e])
}
