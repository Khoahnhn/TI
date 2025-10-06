package search

import (
	"fmt"
)

type grammarES struct{}

func (g *grammarES) QueryNumber(op string, left string, right interface{}) map[string]interface{} {
	m := map[string]interface{}{}
	mm := map[string]interface{}{}
	if op == ">" {
		m["range"] = map[string]interface{}{left: map[string]interface{}{"gt": right}}
		mm["filter"] = m
	}

	if op == "<" {
		m["range"] = map[string]interface{}{left: map[string]interface{}{"lt": right}}
		mm["filter"] = m
	}

	if op == ">=" {
		m["range"] = map[string]interface{}{left: map[string]interface{}{"gte": right}}
		mm["filter"] = m
	}

	if op == "<=" {
		m["range"] = map[string]interface{}{left: map[string]interface{}{"lte": right}}
		mm["filter"] = m
	}

	if op == "=" {
		m["term"] = map[string]interface{}{left: right}
		mm["filter"] = m
	}

	if op == "!=" {
		m["term"] = map[string]interface{}{left: right}
		mm["must_not"] = m
	}

	return map[string]interface{}{
		"bool": mm,
	}
}

func (g *grammarES) QueryString(op string, left string, right interface{}) map[string]interface{} {
	m := map[string]interface{}{}
	mm := map[string]interface{}{}

	if op == "=" {
		m["term"] = map[string]interface{}{left: right}
		mm["filter"] = m
	}
	if op == "!=" {
		m["term"] = map[string]interface{}{left: right}
		mm["must_not"] = m
	}
	if op == "!~" {
		m["match"] = map[string]interface{}{left: fmt.Sprintf("%s", right)}
		mm["must_not"] = m
	}
	if op == "~" {
		m["match"] = map[string]interface{}{left: fmt.Sprintf("%s", right)}
		mm["filter"] = m
	}
	if op == "^" {
		m["prefix"] = map[string]interface{}{left: right}
		mm["filter"] = m
	}
	if op == "$" {
		//m["query_string"] = map[string]interface{}{"default_field": left, "query": fmt.Sprintf("*%s", right)}
		m["wildcard"] = map[string]interface{}{
			left: map[string]interface{}{
				"value":   fmt.Sprintf("?%s", right),
				"boost":   1.0,
				"rewrite": "constant_score",
			},
		}
		mm["filter"] = m
	}

	return map[string]interface{}{
		"bool": mm,
	}
}

func (g *grammarES) QueryBoolean(op string, left string, right interface{}) map[string]interface{} {
	m := map[string]interface{}{}
	mm := map[string]interface{}{}

	if op == "=" {
		m["term"] = map[string]interface{}{left: right}
		mm["filter"] = m
	}
	if op == "!=" {
		m["term"] = map[string]interface{}{left: right}
		mm["must_not"] = m
	}

	return map[string]interface{}{
		"bool": mm,
	}
}

func (g *grammarES) QueryAll(query string) map[string]interface{} {
	return map[string]interface{}{
		"query_string": map[string]interface{}{
			"query": fmt.Sprintf("*%s*", query),
		},
	}
}

func (g *grammarES) String() string {
	return ""
}
