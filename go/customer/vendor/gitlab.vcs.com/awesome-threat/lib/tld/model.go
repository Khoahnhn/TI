package tld

import "fmt"

type Result struct {
	Sub  string
	Root string
	TLD  string
}

func (doc *Result) RootDomain() string {
	if doc.Root == "" || doc.TLD == "" {
		return ""
	}
	// Success
	return fmt.Sprintf("%s.%s", doc.Root, doc.TLD)
}

func (doc *Result) FullDomain() string {
	rootDomain := doc.RootDomain()
	if rootDomain == "" {
		return rootDomain
	}
	fullDomain := rootDomain
	if doc.Sub != "" {
		fullDomain = fmt.Sprintf("%s.%s", doc.Sub, fullDomain)
	}
	// Success
	return fullDomain
}
