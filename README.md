# SSFinder

[![Go Report Card](https://goreportcard.com/badge/github.com/SharokhAtaie/ssfinder)](https://goreportcard.com/report/github.com/SharokhAtaie/ssfinder)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**DOM XSS source/sink finder** — Static analysis tool for finding user-controllable sources (e.g. `location.hash`, `URLSearchParams`) and dangerous sinks (e.g. `innerHTML`, `location.href =`) in JavaScript files.

## Features

### 🔍 Comprehensive Detection
- **Sources**: URL APIs, Storage APIs, Message listeners, React hooks, Router APIs
- **Sinks**: DOM manipulation, React/Vue/Angular frameworks, jQuery, Navigation/Redirects
- **Smart Analysis**: Pre-compiled regex patterns, duplicate detection, beautification for minified JS

### ⚡ Performance Optimizations
- Concurrent URL/file processing with worker pools
- Pre-compiled regex patterns (no runtime compilation overhead)
- Efficient memory usage with streaming support

### 🛠️ Framework Support
- **Vanilla JS**: location, localStorage, postMessage, etc.
- **React**: useSearchParams, useParams, dangerouslySetInnerHTML
- **Next.js**: router.query, route.params
- **Vue/Angular**: v-html, bypassSecurityTrust* APIs
- **jQuery**: .html(), .append(), .prepend()

## Installation

### Go Install (Recommended)
```bash
go install -v github.com/SharokhAtaie/ssfinder@latest
```

## Usage

```bash
# Analyze a local JS file
ssfinder -f script.js

# Analyze all .js files in a directory (recursive, e.g. /tmp/ or ./src/)
ssfinder -f /path/to/dir

# Analyze JS fetched from URL
ssfinder -u https://example.com/app.js

# Multiple URLs from file
ssfinder -l urls.txt

# From stdin
echo "https://example.com/1.js" | ssfinder

# JSON output
ssfinder -f script.js -json

# Save output to file (default format)
ssfinder -f script.js -o report.txt

# Save JSON to file
ssfinder -f script.js -json -o report.json

# Silent: hide banner only; results still shown
ssfinder -f script.js -silent
```

### Flags

| Flag | Description |
|------|-------------|
| `-u`, `-url` | URL to fetch and analyze (JS) |
| `-f`, `-file` | JS file or directory (recursive .js scan) |
| `-l`, `-list` | File with list of URLs (one per line) |
| `-o`, `-output` | Write output to file (JSON if `-json`, else default) |
| `-json` | Output results as JSON |
| `-silent` | Hide banner only; results still shown |

## Example Output

```
▸ Target https://example.com/app.js
─────────────────────────────────────────────────────────────────────
  Sources: 3  Sinks: 2

▸ Sinks
─────────────────────────────────────────────────────────────────────
  [Navigation] Line 45   | location.href = | window.location.href = url;
  [DOM] Line 23          | innerHTML | element.innerHTML = userInput;

▸ Sources
─────────────────────────────────────────────────────────────────────
  [URL] Line 10          | location.hash | var x = location.hash;
  [Storage] Line 15      | localStorage | const data = localStorage.getItem('key');
  [React] Line 30        | useSearchParams | const [params] = useSearchParams();
```

### Output Format Details

- **Summary**: Counts of sources and sinks found
- **Sinks** (Navigation first): `[Navigation]` / `[DOM]` / `[React]` / `[Vue]` / `[Angular]` / `[jQuery]`
- **Sources**: `[URL]` / `[React]` / `[Router]` / `[Storage]` / `[Message]`
- **Priority Highlighting**: Yellow for high-priority findings, dim for lower priority
- **Line Numbers**: Derived from actual file positions (beautified for minified JS)

## Development

### Prerequisites
- Go 1.22 or higher

### Running Tests
```bash
# Run specific test package
go test -v ./analysis

# Run with race detector
go test -race ./...

# Run benchmarks
make benchmark
```

## Project Structure

```
ssfinder/
├── main.go              # CLI entry point and flag parsing
├── analysis/            # Core analysis engine
│   ├── run.go          # Main analysis runner
│   ├── sources.go      # Source pattern definitions
│   ├── sinks.go        # Sink pattern definitions
│   └── position.go     # Line number calculation
├── functions/           # Utility functions
│   └── functions.go    # HTTP fetch, URL validation, JS beautification
├── output/             # Output formatters
│   └── printer.go      # Text and JSON output
├── Makefile            # Build automation
├── Dockerfile          # Container image
```

## Performance Considerations

- **Regex Pre-compilation**: All patterns compiled once at package init (no runtime overhead)
- **Concurrent Processing**: Worker pools for URLs (5 workers) and files (3 workers)
- **Deduplication**: Automatic removal of duplicate findings
- **Memory Efficient**: Streaming processing for large files

## Security Notes

This tool performs **static analysis only** - it does not execute JavaScript code. All pattern matching is done via regular expressions against the source text.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your code passes tests and linters before submitting.

## License

MIT License - see LICENSE file for details

---

**Created by Sharo_k_h**

---

*Created by Sharo_k_h*
