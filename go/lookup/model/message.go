package model

type DNSCrawlMessage struct {
	ID         string                 `json:"id"`
	Source     string                 `json:"source"`
	Value      string                 `json:"value"`
	Published  int64                  `json:"published"`
	Crawled    int64                  `json:"crawled"`
	Attributes map[string]interface{} `json:"attributes"`
	Tags       []string               `json:"tags"`
}
