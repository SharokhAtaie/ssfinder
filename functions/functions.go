package functions

import (
	"fmt"
	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
	"io/ioutil"
	"net/http"
	"net/url"
)

var opts = js.Options{WhileToFor: false, Inline: false}

func HandleErr(str string, err error) {
	if err != nil {
		fmt.Println(str, err)
	}
}

func Get(url string) (string, error) {

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	ast, err := js.Parse(parse.NewInputString(string(body)), opts)
	if err != nil {
		return "", err
	}

	return ast.JSString(), nil
}

func IsValidURL(urlString string) bool {
	_, err := url.ParseRequestURI(urlString)
	if err != nil {
		return false
	}
	return true
}
