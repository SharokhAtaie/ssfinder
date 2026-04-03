// ssfinder finds DOM XSS sources and sinks in JavaScript files.
package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/SharokhAtaie/ssfinder/analysis"
	"github.com/SharokhAtaie/ssfinder/functions"
	"github.com/SharokhAtaie/ssfinder/output"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
)

type options struct {
	url    string
	file   string
	list   string
	silent bool
	json   bool
	output string
}

func main() {
	opt := &options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`
███████╗███████╗███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
██╔════╝██╔════╝██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
███████╗███████╗█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
╚════██║╚════██║██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
███████║███████║██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
╚══════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
			DOM XSS Source/Sink Finder — Created By Sharo_k_h`)
	flagSet.StringVarP(&opt.url, "url", "u", "", "URL to fetch and analyze (JS)")
	flagSet.StringVarP(&opt.file, "file", "f", "", "Local JS file or directory to analyze (recursively finds .js in dirs)")
	flagSet.StringVarP(&opt.list, "list", "l", "", "File with list of URLs (one per line)")
	flagSet.StringVarP(&opt.output, "output", "o", "", "Write output to file (JSON if -json, else default format)")
	flagSet.BoolVar(&opt.silent, "silent", false, "Hide banner only; results still shown")
	flagSet.BoolVar(&opt.json, "json", false, "Output results as JSON")

	if err := flagSet.Parse(); err != nil {
		log.Fatalf("Could not parse flags: %s\n", err)
	}

	if opt.url == "" && opt.list == "" && opt.file == "" && !fileutil.HasStdin() {
		PrintUsage()
		return
	}

	if !opt.silent && !opt.json {
		showBanner()
	}

	// Console always gets output; file (when -o set) gets only results with sources/sinks
	console := os.Stdout
	var outFile *os.File
	if opt.output != "" {
		f, err := os.Create(opt.output)
		if err != nil {
			log.Fatalf("can't create output file: %v", err)
		}
		defer f.Close()
		outFile = f
	}

	if opt.file != "" {
		analyzeFileOrDir(opt.file, console, outFile, opt.json)
		return
	}

	var allURLs []string
	if fileutil.HasStdin() {
		bin, err := io.ReadAll(os.Stdin)
		if err != nil {
			gologger.Error().Msgf("failed to read stdin: %v", err)
			return
		}
		allURLs = strings.Fields(string(bin))
	}
	if opt.url != "" {
		allURLs = append(allURLs, opt.url)
	}
	if opt.list != "" {
		b, err := os.ReadFile(opt.list)
		if err != nil {
			gologger.Error().Msgf("can't open list file: %v", err)
		} else {
			allURLs = append(allURLs, strings.Fields(string(b))...)
		}
	}

	// Process URLs concurrently with worker pool
	const maxWorkers = 5
	urlChan := make(chan string, len(allURLs))
	var wg sync.WaitGroup
	
	// Start workers
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range urlChan {
				processURL(u, console, outFile, opt.json)
			}
		}()
	}
	
	// Send URLs to workers
	for _, u := range allURLs {
		urlChan <- u
	}
	close(urlChan)
	
	// Wait for all workers to complete
	wg.Wait()
}

func analyzeFileOrDir(path string, console io.Writer, outFile *os.File, jsonOut bool) {
	info, err := os.Stat(path)
	if err != nil {
		gologger.Error().Msgf("can't stat path %s: %v", path, err)
		return
	}

	if info.IsDir() {
		var jsFiles []string
		err := filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if fi.IsDir() {
				return nil
			}
			if strings.HasSuffix(strings.ToLower(fi.Name()), ".js") {
				jsFiles = append(jsFiles, p)
			}
			return nil
		})
		if err != nil {
			gologger.Error().Msgf("walk directory: %v", err)
			return
		}
		if len(jsFiles) == 0 {
			gologger.Warning().Msgf("no .js files found in %s", path)
			return
		}
		
		// Process files concurrently
		const maxWorkers = 3
		fileChan := make(chan string, len(jsFiles))
		resultChan := make(chan *analysis.Result, len(jsFiles))
		var wg sync.WaitGroup
		
		// Start workers
		for i := 0; i < maxWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for p := range fileChan {
					res := analyzeOneFile(p)
					if res != nil {
						resultChan <- res
					}
				}
			}()
		}
		
		// Send files to workers
		for _, p := range jsFiles {
			fileChan <- p
		}
		close(fileChan)
		
		// Close result channel when all workers are done
		go func() {
			wg.Wait()
			close(resultChan)
		}()
		
		// Collect results (only those with findings)
		var allResults []*analysis.Result
		for res := range resultChan {
			if hasFindings(res) {
				allResults = append(allResults, res)
			}
		}
		
		if jsonOut {
			if len(allResults) > 0 {
				output.PrintResultsJSON(console, allResults)
				if outFile != nil {
					output.PrintResultsJSON(outFile, allResults)
				}
			}
		} else {
			for _, res := range allResults {
				printResult(console, outFile, res, false)
			}
		}
		return
	}

	res := analyzeOneFile(path)
	if res != nil {
		printResult(console, outFile, res, jsonOut)
	}
}

func processURL(u string, console io.Writer, outFile *os.File, jsonOut bool) {
	if !functions.IsValidURL(u) {
		gologger.Error().Msgf("Invalid URL: %s", u)
		return
	}
	code, err := functions.Get(u)
	if err != nil {
		gologger.Error().Msgf("Failed to fetch %s: %v", u, err)
		return
	}
	// Beautify URL response so minified/one-line JS gets meaningful line numbers
	code = functions.BeautifyJS(code)
	res := analysis.Run(code, u)
	res.Timestamp = time.Now().Format(time.RFC3339)
	printResult(console, outFile, res, jsonOut)
}

func hasFindings(r *analysis.Result) bool {
	return len(r.Sources) > 0 || len(r.Sinks) > 0
}

func analyzeOneFile(path string) *analysis.Result {
	raw, err := os.ReadFile(path)
	if err != nil {
		gologger.Error().Msgf("can't open file %s: %v", path, err)
		return nil
	}
	code := string(raw)
	// If file looks minified (e.g. one or very few lines), beautify so line numbers are useful
	if functions.ShouldBeautify(code) {
		code = functions.BeautifyJS(code)
	}
	res := analysis.Run(code, path)
	res.Timestamp = time.Now().Format(time.RFC3339)
	return res
}

func printResult(console io.Writer, outFile *os.File, res *analysis.Result, jsonOut bool) {
	if !hasFindings(res) {
		return
	}
	if jsonOut {
		output.PrintResultJSON(console, res)
	} else {
		output.PrintResult(console, res)
	}
	if outFile != nil {
		if jsonOut {
			output.PrintResultJSON(outFile, res)
		} else {
			output.PrintResult(outFile, res)
		}
	}
}

func showBanner() {
	gologger.Print().Msgf(`
███████╗███████╗███████╗██╗███╗   ██╗██████╗ ███████╗██████╗ 
██╔════╝██╔════╝██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
███████╗███████╗█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
╚════██║╚════██║██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
███████║███████║██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
╚══════╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
   DOM XSS sources & sinks • Created By Sharo_k_h

`)
}

func PrintUsage() {
	showBanner()
	gologger.Print().Msgf(`Usage:
  ssfinder -u <url>        Analyze JS from URL
  ssfinder -f <file>       Analyze local JS file
  ssfinder -f <dir>        Analyze all .js files in directory (recursive)
  ssfinder -l <urls.txt>   Analyze multiple URLs
  echo https://... | ssfinder   URLs from stdin

Flags:
  -u, -url      URL to fetch and analyze
  -f, -file     JS file or directory (recursive .js)
  -l, -list     File with URLs (one per line)
  -o, -output   Save output to file (JSON if -json, else default)
  -json         Output as JSON
  -silent       Hide banner only; results still shown
`)
}
