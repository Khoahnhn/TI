package virustotal

type (
	AnalysisResultCategory string
	AnalysisResultStatus   string
	AlertSeverity          string
	ThreatVerdict          string
	ThreatSeverityLevel    string
)

const (
	CategoryConfirmedTimeout AnalysisResultCategory = "confirmed-timeout"
	CategoryTimeout          AnalysisResultCategory = "timeout"
	CategoryFailure          AnalysisResultCategory = "failure"
	CategoryHarmless         AnalysisResultCategory = "harmless"
	CategoryUndetected       AnalysisResultCategory = "undetected"
	CategorySuspicious       AnalysisResultCategory = "suspicious"
	CategoryMalicious        AnalysisResultCategory = "malicious"
	CategoryTypeUnsupported  AnalysisResultCategory = "type-unsupported"
)

const (
	AnalysisResultStatusCompleted  AnalysisResultStatus = "completed"
	AnalysisResultStatusQueued     AnalysisResultStatus = "queued"
	AnalysisResultStatusInProgress AnalysisResultStatus = "in-progress"
)

const (
	AlertSeverityCritical      AlertSeverity       = "critical"
	AlertSeverityHigh          AlertSeverity       = "high"
	AlertSeverityMedium        AlertSeverity       = "medium"
	AlertSeverityLow           AlertSeverity       = "low"
	AlertSeverityInfo          AlertSeverity       = "info"
	ThreatVerdictUnknown       ThreatVerdict       = "VERDICT_UNKNOWN"
	ThreatVerdictUndetected    ThreatVerdict       = "VERDICT_UNDETECTED"
	ThreatVerdictSuspicious    ThreatVerdict       = "VERDICT_SUSPICIOUS"
	ThreatVerdictMalicious     ThreatVerdict       = "VERDICT_MALICIOUS"
	ThreatSeverityLevelNone    ThreatSeverityLevel = "SEVERITY_NONE"
	ThreatSeverityLevelLow     ThreatSeverityLevel = "SEVERITY_LOW"
	ThreatSeverityLevelMedium  ThreatSeverityLevel = "SEVERITY_MEDIUM"
	ThreatSeverityLevelHigh    ThreatSeverityLevel = "SEVERITY_HIGH"
	ThreatSeverityLevelUnknown ThreatSeverityLevel = "SEVERITY_UNKNOWN"
)
