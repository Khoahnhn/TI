package udm

import (
	"strings"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
)

type (
	Entity struct {
		EID      string   `json:"-"`
		Noun     Noun     `json:"noun"`
		Metadata Metadata `json:"metadata"`
		// Use for Threat Lookup API
		Evaluate   *Evaluate   `json:"evaluate,omitempty"`
		Enrichment *Enrichment `json:"enrichment,omitempty"`
		Community  *Community  `json:"community,omitempty"`
	}

	EntityJob struct {
		Entity
		CollectedEntityType EntityType `json:"collected_entity_type,omitempty"`
		CollectedInfo       string     `json:"collected_info,omitempty"`
	}

	LogstashEntity struct {
		Entity
		Metadata LogstashMetadata `json:"@metadata"`
	}
)

func (doc *Entity) GetID() string {
	// Success
	return doc.Metadata.GetID()
}

func (doc *Entity) GenID() {
	// Success
	doc.Metadata.GenID()
	doc.SetEID(doc.GetID())
}

func (doc *Entity) SetEID(id string) {
	// Success
	doc.EID = id
}

func (doc *Entity) GetValue() string {
	// Success
	return doc.Metadata.Value
}

func (doc *Entity) GetType() EntityType {
	// Success
	return doc.Metadata.EntityType
}

func (doc *Entity) IsExpired() bool {
	now, _ := clock.Now(clock.Local)
	if doc.Metadata.ValidToTimestamp == 0 {
		return false
	}
	// Success
	return doc.Metadata.ValidToTimestamp <= clock.UnixMilli(now)
}

func NewEntity(value string, kind EntityType) *Entity {
	now, _ := clock.Now(clock.Local)
	nowTs := clock.UnixMilli(now)
	value = strings.TrimSpace(value)
	entity := Entity{
		Metadata: Metadata{
			CollectedTimestamp:    nowTs,
			CreationTimestamp:     nowTs,
			ModificationTimestamp: nowTs,
			ValidFromTimestamp:    nowTs,
			EntityType:            kind,
			Value:                 value,
			Label:                 value,
			Tags:                  make([]string, 0),
			Attributes:            map[string]string{},
			VendorName:            DefaultVendorName,
			ProductName:           DefaultProductName,
			ProductVersion:        DefaultProductVersion,
			SourceName:            DefaultSourceName,
			SourceType:            SourceTypeUnspecified,
		},
	}
	switch kind {
	case EntityTypeDomain:
		entity.Noun.Domain = &Domain{}
	case EntityTypeIPAddress:
		entity.Noun.IP = &IP{}
	case EntityTypeURL:
		entity.Noun.URL = &URL{}
	case EntityTypeFile:
		entity.Noun.File = &File{}
	case EntityTypeEmail:
		entity.Noun.Email = &Email{}
	case EntityTypeRegistry:
		entity.Noun.Registry = &Registry{}
	case EntityTypeUser:
		entity.Noun.User = &User{}
	case EntityTypePopularityRank:
		entity.Noun.PopularityRank = &PopularityRank{}
	case EntityTypeWhois:
		entity.Noun.Whois = &Whois{}
	case EntityTypeArtifact:
		entity.Noun.Artifact = &Artifact{}
	case EntityTypeSSLCertificate:
		entity.Noun.SSLCertificate = &SSLCertificate{}
	case EntityTypeHTTPRequest:
		entity.Noun.HTTPRequest = &HTTPRequest{}
	case EntityTypePermission:
		entity.Noun.Permission = &Permission{}
	case EntityTypeDNSRecord:
		entity.Noun.DNSRecord = &DNSRecord{}
	case EntityTypeSecurityResult:
		entity.Noun.SecurityResult = &SecurityResult{}
	case EntityTypeVerdictInfo:
		entity.Noun.VerdictInfo = &VerdictInfo{}
	case EntityTypeRelationship:
		entity.Noun.Relationship = &Relationship{}
	}
	entity.GenID()
	// Success
	return &entity
}
