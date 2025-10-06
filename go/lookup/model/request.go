package model

import "gitlab.viettelcyber.com/awesome-threat/library/udm"

type (
	RequestLookup struct {
		Value      string         `json:"value" validate:"required"`
		EntityType udm.EntityType `json:"entity_type"`
		Sections   []string       `json:"sections"`
	}

	RequestIdentify struct {
		Values []string `json:"values" validate:"required"`
	}

	RequestLookupSingle struct {
		Value    string                     `json:"value" validate:"required"`
		Sections map[string]*RequestSection `json:"sections"`
	}

	RequestSection struct {
		Limit  int  `json:"limit"`
		Offset int  `json:"offset"`
		Flat   bool `json:"flat"`
	}

	RequestLookupMultiple struct {
		Values  []string `json:"values" validate:"required"`
		Invalid []string `json:"-"`
	}
)
