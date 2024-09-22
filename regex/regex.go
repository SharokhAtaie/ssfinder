package regex

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

const (
	GreenStart  = "\033[0;32m"
	BlueStart   = "\033[0;34m"
	CyanStart   = "\033[1;36m"
	OrangeStart = "\033[0;33m"
	End         = "\033[0m"
)

func DomSinker(str, url string) {

	regexList := []string{
		`(?i)\.innerHTML.*`,
		`(?i)document\.write\(.*\)`,
		`(?i)document\.writeln\(.*\)`,
		`(?i)executeSql\(.*\)`,
		`(?i)script\.src|script\.text|script\.textContent|script\.innerText.*`,
		`(?i)eval\(.*\)`,
		`(?i)execScript\(.*\)`,
		`(?i)Range\.createContextualFragment\(.*\)`,
		`(?i)window\.location\s+?=.*`,
		`(?i)location\.href\s+?=.*`,
		`(?i)location\.search\s+?=.*`,
		`(?i)document\.domain\s+?=.*`,
		`(?i)window\.location\.hash\s+?=.*`,
		`(?i)window\.open.*`,
		`(?i)\.outerHTML\s+?=.*?.*?(\+).*`,
		`(?i)\.insertAdjacentHTML\s*=\s*.*?\+.*`,
		`(?i)\.onEventName\s*=\s*.*?\+.*`,
		`(?i)crypto\.generateCRMFRequest.*`,
	}

	fmt.Printf("%s[Link]%s %s\n\n", BlueStart, End, url)

	var wg sync.WaitGroup
	var mu sync.Mutex
	resultFound := false

	lines := strings.Split(str, "\n") // Split input into lines

	for _, regex := range regexList {
		wg.Add(1)
		go func(regex string) {
			defer wg.Done()
			re := regexp.MustCompile(regex)

			var matches []string
			for i, line := range lines {
				if re.MatchString(line) {
					// Find the match position and length
					loc := re.FindStringIndex(line)
					if loc != nil {
						// Extract 20 characters before the match (handle cases where there are fewer than 20 characters)
						start := loc[0] - 20
						if start < 0 {
							start = 0
						}
						prefix := line[start:loc[0]]

						// Extract only 60 characters of the match
						matchPart := line[loc[0]:loc[1]]
						if len(matchPart) > 60 {
							matchPart = matchPart[:60]
						}

						// Extract 20 characters after the match (if needed)
						end := loc[1]
						if end+20 > len(line) {
							end = len(line)
						} else {
							end += 20
						}
						suffix := line[loc[1]:end]

						// Combine prefix, highlighted match, and suffix
						highlightedLine := fmt.Sprintf("%s%s%s", prefix, GreenStart+matchPart+End, suffix)

						// Collect match and its line number
						matches = append(matches, fmt.Sprintf("Line %s%d%s: ...%s", OrangeStart, i+1, End, highlightedLine))
					}
				}
			}

			if len(matches) > 0 {
				// Lock only while printing the result
				mu.Lock()
				defer mu.Unlock()

				// Print compact boxed format
				fmt.Printf("┌────────────────────────────────────────────────────────────────────────┐\n")
				fmt.Printf("│  %s%s%s \n", CyanStart, regex, End)
				fmt.Printf("└────────────────────────────────────────────────────────────────────────┘\n")

				for _, match := range matches {
					fmt.Println(match)
				}

				fmt.Printf("──────────────────────────────────────────────────────────────────────────\n\n")
				resultFound = true
			}
		}(regex)
	}

	wg.Wait()

	if !resultFound {
		fmt.Println("No results found")
	}
}
