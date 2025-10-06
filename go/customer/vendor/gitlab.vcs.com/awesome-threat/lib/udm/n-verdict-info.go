package udm

type VerdictInfo struct {
	VerdictTime       int64       `json:"verdict_time,omitempty"`
	EntityValue       string      `json:"entity_value,omitempty"`
	EntityType        EntityType  `json:"entity_type,omitempty"`
	VerdictType       VerdictType `json:"verdict_type,omitempty"`
	VerdictName       string      `json:"verdict_name,omitempty"`
	VerdictVersion    string      `json:"verdict_version,omitempty"`
	VerdictResponse   string      `json:"verdict_response,omitempty"`
	RiskScore         *int        `json:"risk_score,omitempty"`
	ConfidenceScore   int         `json:"confidence_score,omitempty"`
	VerdictSummary    string      `json:"verdict_summary,omitempty"`
	VerdictCategories []string    `json:"verdict_categories,omitempty"`
	VerdictTags       []string    `json:"verdict_tags,omitempty"`
}
