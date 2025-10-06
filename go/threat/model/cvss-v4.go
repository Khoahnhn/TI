package model

import "strings"

type (
	CvssV4 struct {
		Vector CvssVectorV4 `json:"cvssV4"`
	}

	CvssVectorV4 struct {
		Version                           string  `json:"version"`
		VectorString                      string  `json:"vectorString"`
		BaseScore                         float32 `json:"baseScore"`
		BaseSeverity                      string  `json:"baseSeverity"`
		AttackVector                      string  `json:"attackVector"`
		AttackComplexity                  string  `json:"attackComplexity"`
		AttackRequirements                string  `json:"attackRequirements"`
		PrivilegesRequired                string  `json:"privilegesRequired"`
		UserInteraction                   string  `json:"userInteraction"`
		VulnConfidentialityImpact         string  `json:"vulnConfidentialityImpact"`
		VulnIntegrityImpact               string  `json:"vulnIntegrityImpact"`
		VulnAvailabilityImpact            string  `json:"vulnAvailabilityImpact"`
		SubConfidentialityImpact          string  `json:"subConfidentialityImpact"`
		SubIntegrityImpact                string  `json:"subIntegrityImpact"`
		SubAvailabilityImpact             string  `json:"subAvailabilityImpact"`
		ExploitMaturity                   string  `json:"exploitMaturity"`
		ConfidentialityRequirement        string  `json:"confidentialityRequirement"`
		IntegrityRequirement              string  `json:"integrityRequirement"`
		AvailabilityRequirement           string  `json:"availabilityRequirement"`
		ModifiedAttackVector              string  `json:"modifiedAttackVector"`
		ModifiedAttackComplexity          string  `json:"modifiedAttackComplexity"`
		ModifiedAttackRequirements        string  `json:"modifiedAttackRequirements"`
		ModifiedPrivilegesRequired        string  `json:"modifiedPrivilegesRequired"`
		ModifiedUserInteraction           string  `json:"modifiedUserInteraction"`
		ModifiedVulnConfidentialityImpact string  `json:"modifiedVulnConfidentialityImpact"`
		ModifiedVulnIntegrityImpact       string  `json:"modifiedVulnIntegrityImpact"`
		ModifiedVulnAvailabilityImpact    string  `json:"modifiedVulnAvailabilityImpact"`
		ModifiedSubConfidentialityImpact  string  `json:"modifiedSubConfidentialityImpact"`
		ModifiedSubIntegrityImpact        string  `json:"modifiedSubIntegrityImpact"`
		ModifiedSubAvailabilityImpact     string  `json:"modifiedSubAvailabilityImpact"`
		Safety                            string  `json:"safety"`
		Automatable                       string  `json:"automatable"`
		Recovery                          string  `json:"recovery"`
		ValueDensity                      string  `json:"valueDensity"`
		VulnerabilityResponseEffort       string  `json:"vulnerabilityResponseEffort"`
		ProviderUrgency                   string  `json:"providerUrgency"`
	}
)

func (doc *CvssVectorV4) Result() map[string]interface{} {
	// Success
	return map[string]interface{}{
		"Attack Complexity":   strings.Title(strings.ToLower(doc.AttackComplexity)),
		"Attack Vector":       strings.Title(strings.ToLower(doc.AttackVector)),
		"Privileges Required": strings.Title(strings.ToLower(doc.PrivilegesRequired)),
		"User Interaction":    strings.Title(strings.ToLower(doc.UserInteraction)),
		"Base Severity":       strings.Title(strings.ToLower(doc.BaseSeverity)),
	}
}
