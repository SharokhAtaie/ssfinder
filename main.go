package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

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
		file, err := os.ReadFile(opt.list)
		functions.HandleErr("can't open list file: ", err)
		allURLs = append(allURLs, strings.Fields(string(file))...)
	}

	for _, u := range allURLs {
		if !functions.IsValidURL(u) {
			gologger.Error().Msgf("Invalid URL: %s", u)
			continue
		}
		code, err := functions.Get(u)
		if err != nil {
			gologger.Error().Msgf("Failed to fetch %s: %v", u, err)
			continue
		}
		// Beautify URL response so minified/one-line JS gets meaningful line numbers
		code = functions.BeautifyJS(code)
		res := analysis.Run(code, u)
		printResult(console, outFile, res, opt.json)
	}
}

func analyzeFileOrDir(path string, console io.Writer, outFile *os.File, jsonOut bool) {
	info, err := os.Stat(path)
	functions.HandleErr("can't stat path: ", err)

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
		functions.HandleErr("walk directory: ", err)
		if len(jsFiles) == 0 {
			gologger.Warning().Msgf("no .js files found in %s", path)
			return
		}
		if jsonOut {
			var allResults, fileResults []*analysis.Result
			for _, p := range jsFiles {
				res := analyzeOneFile(p)
				if res != nil {
					allResults = append(allResults, res)
					if hasFindings(res) {
						fileResults = append(fileResults, res)
					}
				}
			}
			output.PrintResultsJSON(console, allResults)
			if outFile != nil && len(fileResults) > 0 {
				output.PrintResultsJSON(outFile, fileResults)
			}
		} else {
			for _, p := range jsFiles {
				res := analyzeOneFile(p)
				if res != nil {
					printResult(console, outFile, res, false)
				}
			}
		}
		return
	}

	res := analyzeOneFile(path)
	if res != nil {
		printResult(console, outFile, res, jsonOut)
	}
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
	return analysis.Run(code, path)
}

func printResult(console io.Writer, outFile *os.File, res *analysis.Result, jsonOut bool) {
	// Always show in console
	if jsonOut {
		output.PrintResultJSON(console, res)
	} else {
		output.PrintResult(console, res)
	}
	// Save to file only if target has sources or sinks
	if outFile != nil && hasFindings(res) {
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
