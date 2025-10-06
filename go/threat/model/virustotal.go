package model

import "gitlab.viettelcyber.com/awesome-threat/library/virustotal"

type (
	RequestVirustotalFileReport struct {
		Value string `json:"value"`
		Force bool   `json:"force"`
	}

	ResponseVirustotalFileReport struct {
		Success bool               `json:"success"`
		Message string             `json:"message"`
		Detail  *virustotal.FileV3 `json:"detail`
	}
)
