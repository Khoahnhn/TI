package tld

import "github.com/joeguo/tldextract"

type service struct {
	model *tldextract.TLDExtract
}

func NewService(cache string) Service {
	extractor, err := tldextract.New(cache, false)
	if err != nil {
		panic(err)
	}
	// Success
	return &service{model: extractor}
}

func (inst *service) Extract(value string) *Result {
	// Success
	result := inst.model.Extract(value)
	// Success
	return &Result{
		Sub:  result.Sub,
		Root: result.Root,
		TLD:  result.Tld,
	}
}
