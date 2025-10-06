package udm

type SecurityResult struct {
	FirstDiscoveredTime  int64        `json:"first_discovered_time,omitempty"`
	LastDiscoveredTime   int64        `json:"last_discovered_time,omitempty"`
	LastUpdatedTime      int64        `json:"last_updated_time,omitempty"`
	ThreatVerdictName    string       `json:"threat_verdict_name,omitempty"`
	ThreatVerdictVersion string       `json:"threat_verdict_version,omitempty"`
	ThreatStatus         ThreatStatus `json:"threat_status,omitempty"`
	RiskScore            *int         `json:"risk_score,omitempty"`
	Categories           []string     `json:"categories,omitempty"`
	Tags                 []string     `json:"tags,omitempty"`
	Confidence           Confidence   `json:"confidence,omitempty"`
	ConfidenceScore      int          `json:"confidence_score,omitempty"`
	Priority             Priority     `json:"priority,omitempty"`
	Severity             Severity     `json:"severity,omitempty"`
	Description          string       `json:"description,omitempty"`
	Summary              string       `json:"summary,omitempty"`
	PrivateVTI           bool         `json:"private_vti,omitempty"`
}
