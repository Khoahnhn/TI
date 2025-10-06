package model

import (
	"ws-lookup/defs"

	"gitlab.viettelcyber.com/awesome-threat/library/udm"
)

type (
	ResponseEnrichment struct {
		Success bool        `json:"success"`
		Message string      `json:"message"`
		Detail  *udm.Entity `json:"detail"`
	}

	ResponseEnrichmentBase struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	ResponseLookup struct {
		Entity         *udm.Entity         `json:"entity,omitempty"`
		Enrichment     *udm.Enrichment     `json:"enrichment,omitempty"`
		SecurityResult *udm.SecurityResult `json:"security_result,omitempty"`
		Community      *udm.Community      `json:"community,omitempty"`
	}
)

type (
	ResponseLookupMultiple struct {
		Data   []*LookupMultipleItem `json:"data,omitempty"`
		Failed []*LookupMultipleItem `json:"failed,omitempty"`
	}

	LookupMultipleItem struct {
		Value          string         `json:"value,omitempty"`
		RiskScore      *int           `json:"risk_score,omitempty"`
		Categories     []string       `json:"categories,omitempty"`
		StatusIOC      defs.StatusIOC `json:"status_ioc,omitempty"`
		Registrar      string         `json:"registrar,omitempty"`
		Registrant     string         `json:"registrant,omitempty"`
		Subnet         string         `json:"subnet,omitempty"`
		ASN            int            `json:"asn,omitempty"`
		ASL            string         `json:"asl,omitempty"`
		Location       string         `json:"location,omitempty"`
		FileType       string         `json:"file_type,omitempty"`
		FirstSeen      int64          `json:"first_seen,omitempty"`
		LastSeen       int64          `json:"last_seen,omitempty"`
		CreationTime   int64          `json:"creation_time,omitempty"`
		ExpirationTime int64          `json:"expiration_time,omitempty"`
		PrivateVTI     bool           `json:"private_vti,omitempty"`
		Whitelist      bool           `json:"whitelist,omitempty"`
		Error          string         `json:"error,omitempty"`
	}

	ResponseLookupMultipleCVE struct {
		Data   []*LookupMultipleItemCVE `json:"data,omitempty"`
		Failed []*LookupMultipleItemCVE `json:"failed,omitempty"`
	}

	LookupMultipleItemCVE struct {
		Value     string    `json:"value,omitempty"`
		Created   int64     `json:"created,omitempty"`
		Published int64     `json:"published,omitempty"`
		Approved  int64     `json:"approved,omitempty"`
		Products  []string  `json:"products,omitempty"`
		Score     *CVEScore `json:"score,omitempty"`
		Error     string    `json:"error,omitempty"`
	}
)

type (
	ResponseEnrichmentPassiveDNSDomain struct {
		ResponseEnrichmentBase
		Detail *udm.ResponseEnrichmentPassiveDNSDomain `json:"detail"`
	}

	ResponseEnrichmentSubdomain struct {
		ResponseEnrichmentBase
		Detail *udm.ResponseEnrichmentSubdomain `json:"detail"`
	}

	ResponseEnrichmentSibling struct {
		ResponseEnrichmentBase
		Detail *udm.ResponseEnrichmentSiblingDomain `json:"detail"`
	}
)

type (
	ResponseEnrichmentPassiveDNSIPAddress struct {
		ResponseEnrichmentBase
		Detail *udm.ResponseEnrichmentPassiveDNSIPAddress `json:"detail"`
	}

	ResponseEnrichmentSubnet struct {
		ResponseEnrichmentBase
		Detail *udm.ResponseEnrichmentSubnet `json:"detail"`
	}
)
