package model

import "strings"

type (
	CvssV3 struct {
		Vector              CvssVectorV3 `json:"cvssV3"`
		ExploitabilityScore float32      `json:"exploitabilityScore"`
		ImpactScore         float32      `json:"impactScore"`
	}

	CvssVectorV3 struct {
		Version               string  `json:"version"`
		VectorString          string  `json:"vectorString"`
		AttackVector          string  `json:"attackVector"`
		AttackComplexity      string  `json:"attackComplexity"`
		PrivilegesRequired    string  `json:"privilegesRequired"`
		UserInteraction       string  `json:"userInteraction"`
		Scope                 string  `json:"scope"`
		ConfidentialityImpact string  `json:"confidentialityImpact"`
		IntegrityImpact       string  `json:"integrityImpact"`
		AvailabilityImpact    string  `json:"availabilityImpact"`
		BaseScore             float32 `json:"baseScore"`
		BaseSeverity          string  `json:"baseSeverity"`
	}
)

func (doc *CvssVectorV3) Result() map[string]interface{} {
	// Success
	return map[string]interface{}{
		"Attack Complexity":      strings.Title(strings.ToLower(doc.AttackComplexity)),
		"Attack Vector":          strings.Title(strings.ToLower(doc.AttackVector)),
		"Availability Impact":    strings.Title(strings.ToLower(doc.AvailabilityImpact)),
		"Confidentiality Impact": strings.Title(strings.ToLower(doc.ConfidentialityImpact)),
		"Integrity Impact":       strings.Title(strings.ToLower(doc.IntegrityImpact)),
		"Privileges Required":    strings.Title(strings.ToLower(doc.PrivilegesRequired)),
		"Scope":                  strings.Title(strings.ToLower(doc.Scope)),
		"User Interaction":       strings.Title(strings.ToLower(doc.UserInteraction)),
		"Base Severity":          strings.Title(strings.ToLower(doc.BaseSeverity)),
	}
}
