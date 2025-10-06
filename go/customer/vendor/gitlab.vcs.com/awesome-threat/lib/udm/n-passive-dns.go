package udm

type (
	PassiveDNS struct {
		ResolutionTime int64  `json:"resolution_time,omitempty"`
		Domain         string `json:"domain,omitempty"`
		IPAddress      string `json:"ipaddress,omitempty"`
	}

	PassiveDNSDomain struct {
		PassiveDNS
		ASN       int    `json:"asn,omitempty"`
		ASL       string `json:"asl,omitempty"`
		RiskScore *int   `json:"risk_score,omitempty"`
	}

	PassiveDNSIPAddress struct {
		PassiveDNS
		Registrar string `json:"registrar,omitempty"`
		RiskScore *int   `json:"risk_score,omitempty"`
	}
)
