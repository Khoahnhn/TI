package udm

type (
	DNSRecord struct {
		A     []string `json:"a,omitempty"`
		AAAA  []string `json:"aaaa,omitempty"`
		CName []string `json:"cname,omitempty"`
		MX    []string `json:"mx,omitempty"`
		TXT   []string `json:"txt,omitempty"`
		NS    []string `json:"ns,omitempty"`
	}
)
