package virustotal

type (
	Analysis struct {
		Date    int64                      `json:"date"`
		Results map[string]*AnalysisResult `json:"results"`
		Stats   *AnalysisStats             `json:"stats"`
		Status  AnalysisResultStatus       `json:"status"`
	}

	AnalysisResult struct {
		Category      AnalysisResultCategory `json:"category"`
		EngineName    string                 `json:"engine_name"`
		EngineUpdate  string                 `json:"engine_update,omitempty"`
		EngineVersion string                 `json:"engine_version,omitempty"`
		Method        string                 `json:"method"`
		Result        string                 `json:"result"`
	}

	AnalysisStats struct {
		Harmless         int `json:"harmless,omitempty"`
		Malicious        int `json:"malicious,omitempty"`
		Suspicious       int `json:"suspicious,omitempty"`
		Timeout          int `json:"timeout,omitempty"`
		Undetected       int `json:"undetected,omitempty"`
		ConfirmedTimeout int `json:"confirmed-timeout,omitempty"`
		Failure          int `json:"failure,omitempty"`
		TypeUnsupported  int `json:"type-unsupported,omitempty"`
	}
)
