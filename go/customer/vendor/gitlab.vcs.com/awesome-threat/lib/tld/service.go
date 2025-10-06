package tld

type Service interface {
	Extract(value string) *Result
}
