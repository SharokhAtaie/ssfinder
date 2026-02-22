# SSFinder

**DOM XSS source/sink finder** — finds user-controllable sources (e.g. `location.hash`, `URLSearchParams`) and dangerous sinks (e.g. `innerHTML`, `location.href =`) in JavaScript.

## Features

- **Sources**: URL, Storage, Message, React, Router (with importance highlighting)
- **Sinks**: DOM, React, Vue, Angular, jQuery, Navigation (printed with Navigation first)
- **CLI**: Colored output, category labels, `-json`, `-o` to save to file, directory scan

## Installation

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

## Example output

- **Summary**: Counts of sources and sinks.
- **Sinks** (Navigation first): `[Navigation]` / `[DOM]` / `[React]` etc., then `Line N | name | snippet`.
- **Sources**: `[URL]` / `[React]` / `[Storage]` / `[Message]` etc., then `Line N | name | snippet`.
- Line numbers are derived from the file/response (1 + newlines before the match).

---

*Created by Sharo_k_h*
