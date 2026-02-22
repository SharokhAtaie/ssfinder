// Package functions provides HTTP fetch, URL validation, and JS beautification.
package functions

import (
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
)

var jsParseOpts = js.Options{}

// MaxLinesConsideredMinified: if content has this many or fewer lines, we treat it as minified and beautify.
const MaxLinesConsideredMinified = 5

// ShouldBeautify reports whether content looks minified (very few newlines) and should be beautified
// so that analysis line numbers are meaningful. Used for file input; URL input is always beautified.
func ShouldBeautify(code string) bool {
	return strings.Count(code, "\n") <= MaxLinesConsideredMinified
}

// BeautifyJS parses the input as JavaScript and returns a formatted version,
// so that line numbers from analysis are meaningful. If parsing fails, returns the original content.
func BeautifyJS(code string) string {
	ast, err := js.Parse(parse.NewInputString(code), jsParseOpts)
	if err != nil {
		return code
	}
	return ast.JSString()
}

// Get fetches the URL and returns the raw response body.
// Uses a common User-Agent so CDNs/servers return JS instead of HTML.
func Get(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SSFinder/1.0)")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func IsValidURL(urlString string) bool {
	_, err := url.ParseRequestURI(urlString)
	if err != nil {
		return false
	}
	return true
}
