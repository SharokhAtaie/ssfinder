package main

import (
	"github.com/SharokhAtaie/ssfinder/functions"
	"github.com/SharokhAtaie/ssfinder/regex"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
	"io"
	"log"
	"os"
	"strings"
)

type options struct {
	url    string
	file   string
	list   string
	silent bool
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
			Created By Sharo_k_h`)
	flagSet.StringVarP(&opt.url, "url", "u", "", "url for analyze")
	flagSet.StringVarP(&opt.file, "file", "f", "", "js file to analyze")
	flagSet.StringVarP(&opt.list, "list", "l", "", "list of urls for analyze")
	flagSet.BoolVar(&opt.silent, "silent", false, "show silent output")

	if err := flagSet.Parse(); err != nil {
		log.Fatalf("Could not parse flags: %s\n", err)
	}

	if opt.url == "" && opt.list == "" && opt.file == "" && !fileutil.HasStdin() {
		PrintUsage()
		return
	}

	if opt.silent == false {
		showBanner()
	}

	if opt.file != "" {
		file, err := os.ReadFile(opt.file)
		functions.HandleErr("can't open the file: ", err)

		ast, err := js.Parse(parse.NewInputString(string(file)), js.Options{WhileToFor: false, Inline: false})
		if err != nil {
			gologger.Error().Msgf("Response is not valid JS code: %s\n%s", opt.file, err)
		}

		regex.DomSinker(ast.JSString(), opt.file)
		return
	}

	var AllURLs []string

	if fileutil.HasStdin() {
		bin, err := io.ReadAll(os.Stdin)
		if err != nil {
			gologger.Error().Msgf("failed to read file %v got %v", opt.list, err)
		}

		AllURLs = strings.Fields(string(bin))
	}

	if opt.url != "" {
		AllURLs = append(AllURLs, opt.url)
	}

	if opt.list != "" {
		file, err := os.ReadFile(opt.list)
		functions.HandleErr("can't open the file: ", err)
		list := strings.Fields(string(file))

		AllURLs = append(AllURLs, list...)
	}

	AnalyzeURLs(AllURLs)

	return
}

func AnalyzeURLs(urls []string) {
	for _, url := range urls {
		if functions.IsValidURL(url) {
			resp, err := functions.Get(url)
			if err != nil {
				gologger.Error().Msgf("Response is not valid JS code: %s\n%s", url, err)
				continue
			}
			regex.DomSinker(resp, url)
		} else {
			gologger.Error().Msgf("Invalid URL: %s", url)
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
`)
	gologger.Print().Msgf("             	Created By Sharo_k_h\n\n")
}

func PrintUsage() {
	showBanner()
	gologger.Print().Msgf(`Flags:
   -u, -url string   url for analyze
   -f, -file string  js file to analyze
   -l, -list string  list of urls for analyze
   -silent           show silent output`)
}
