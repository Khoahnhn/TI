package defs

type (
	PredictStatus string
)

const (
	// IOC
	TypeDomain       = "domain"
	TypeIPAddress    = "ipaddress"
	TypeURL          = "url"
	TypeSample       = "sample"
	TypeEmail        = "email"
	TypeUnknown      = "unknown"
	StatusMalicious  = 1
	StatusClean      = 0
	StatusUnknown    = -1
	StatusSuspicious = -2
	DefaultIOCSort   = "-updated_date"
	DefaultIOCSource = "threat_analyst"
	DefaultIOCRank   = -101

	ActionCreateIOC = "Create IOC"
	ActionEditIOC   = "Update IOC: %s"

	PredictStatusMalicious  PredictStatus = "malicious"
	PredictStatusSuspicious PredictStatus = "suspicious"
	PredictStatusClean      PredictStatus = "clean"
	PredictStatusError      PredictStatus = "error"
	PredictStatusUnknown    PredictStatus = "unknown"

	VerboseUnsupportedIndicatorType              = "This type of IOC is not supported yet"
	VerbosePredictFailed                         = "Predict failed"
	VerbosePredictMaliciousVirustotalWithTrustAV = "Virustotal Result:\nTrusted AVs (%s) predicted this IOC as malicious\nMalicious: %d\nSuspicious: %d\nType Unsupported: %d\nUndetected: %d\nHarmless: %d\nFailure: %d\nTimeout: %d\nConfirmed Timeout: %d"
	VerbosePredictMaliciousVirustotal            = "Virustotal Result:\nMalicious: %d\nSuspicious: %d\nType Unsupported: %d\nUndetected: %d\nHarmless: %d\nFailure: %d\nTimeout: %d\nConfirmed Timeout: %d"
)

var (
	MappingIOCType = map[string]string{
		TypeDomain:    "Domain",
		TypeIPAddress: "IP Address",
		TypeURL:       "URL",
		TypeSample:    "Sample",
		TypeEmail:     "Email",
		TypeUnknown:   "Unknown",
	}

	MappingIOCStatus = map[int]string{
		StatusMalicious:  "Malicious",
		StatusClean:      "Clean",
		StatusUnknown:    "Unknown",
		StatusSuspicious: "Suspicious",
	}

	EnumIOCCategories = []string{
		"Unknown",
		"Ransomware",
		"Backdoor",
		"DynamicDNS",
		"Sinkhole",
		"Phishing",
		"Compromised",
		"Trojan Banking",
		"Adware",
		"Mobile",
		"Skimmer",
		"APT",
		"Other",
		"Trojan",
		"Botnet",
		"Firmware",
		"DGA",
		"Generic",
		"Rootkit",
		"Stealer",
		"Bootkit",
		"Spyware",
		"Miner",
		"Exploit Vuln",
		"RAT",
		"Fileless Malware",
		"Worm",
		"Wiper",
		"Loader",
	}

	EnumIOCRegex = []string{
		"exactly",
		"wildcard",
	}
)
