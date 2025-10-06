package helper

import (
	"strings"

	"github.com/joeguo/tldextract"
)

var (
	tldExtractor *tldextract.TLDExtract
)

func ExtractDomain(domain string) *tldextract.Result {
	// Success
	return tldExtractor.Extract(domain)
}

func UniqArray(arr []string) []string {
	m := map[string]bool{}
	for _, s := range arr {
		s = strings.TrimSpace(s)
		if s != "" {
			m[s] = true
		}
	}

	var newArr []string
	for s := range m {
		newArr = append(newArr, s)
	}
	return newArr
}
