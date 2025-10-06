package search

type grammarQuery interface {
	QueryNumber(op string, left string, right interface{}) map[string]interface{}
	QueryString(op string, left string, right interface{}) map[string]interface{}
	QueryBoolean(op string, left string, right interface{}) map[string]interface{}
	QueryAll(query string) map[string]interface{}
	String() string
}
