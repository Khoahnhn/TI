package udm

type (
	Domain struct {
		Sub  string `json:"sub,omitempty"`
		Name string `json:"name,omitempty"`
		TLD  string `json:"tld,omitempty"`
		Root string `json:"root,omitempty"`
	}

	Subdomain struct {
		FullDomain  string `json:"full_domain,omitempty"`
		RootDomain  string `json:"root_domain,omitempty"`
		ResolveTime int64  `json:"resolve_time,omitempty"`
		IPAddress   string `json:"ipaddress,omitempty"`
		RiskScore   *int   `json:"risk_score,omitempty"`
	}

	SiblingDomain struct {
		FullDomain  string `json:"full_domain,omitempty"`
		RootDomain  string `json:"root_domain,omitempty"`
		ResolveTime int64  `json:"resolve_time,omitempty"`
		IPAddress   string `json:"ipaddress,omitempty"`
		RiskScore   *int   `json:"risk_score,omitempty"`
	}
)
