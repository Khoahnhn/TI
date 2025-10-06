package model

import "strings"

type (
	CvssV2 struct {
		Vector                  CvssVectorV2 `json:"cvssV2"`
		Severity                string       `json:"severity"`
		ExploitabilityScore     float32      `json:"exploitabilityScore"`
		ImpactScore             float32      `json:"impactScore"`
		AcInsufInfo             bool         `json:"acInsufInfo"`
		ObtainAllPrivilege      bool         `json:"obtainAllPrivilege"`
		ObtainUserPrivilege     bool         `json:"obtainUserPrivilege"`
		ObtainOtherPrivilege    bool         `json:"obtainOtherPrivilege"`
		UserInteractionRequired bool         `json:"userInteractionRequired"`
	}

	CvssVectorV2 struct {
		Version               string  `json:"version"`
		VectorString          string  `json:"vectorString"`
		AccessVector          string  `json:"accessVector"`
		AccessComplexity      string  `json:"accessComplexity"`
		Authentication        string  `json:"authentication"`
		ConfidentialityImpact string  `json:"confidentialityImpact"`
		IntegrityImpact       string  `json:"integrityImpact"`
		AvailabilityImpact    string  `json:"availabilityImpact"`
		BaseScore             float32 `json:"baseScore"`
	}
)

func (doc *CvssVectorV2) Result() map[string]interface{} {
	// Success
	return map[string]interface{}{
		"Access Vector":          strings.Title(strings.ToLower(doc.AccessVector)),
		"Access Complexity":      strings.Title(strings.ToLower(doc.AccessComplexity)),
		"Authentication":         strings.Title(strings.ToLower(doc.Authentication)),
		"Availability Impact":    strings.Title(strings.ToLower(doc.AvailabilityImpact)),
		"Confidentiality Impact": strings.Title(strings.ToLower(doc.ConfidentialityImpact)),
		"Integrity Impact":       strings.Title(strings.ToLower(doc.IntegrityImpact)),
	}
}
