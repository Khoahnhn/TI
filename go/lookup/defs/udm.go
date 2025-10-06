package defs

import "gitlab.viettelcyber.com/awesome-threat/library/udm"

var emptyStruct = struct{}{}

var EnumEntityType = map[udm.EntityType]struct{}{
	udm.EntityTypeIPAddress: emptyStruct,
	udm.EntityTypeDomain:    emptyStruct,
	udm.EntityTypeURL:       emptyStruct,
	udm.EntityTypeFile:      emptyStruct,
}

const (
	SectionEnrichment = "enrichment"
	SectionCommunity  = "community"
	SectionEvaluate   = "evaluate"
)

var EnumSection = map[string]struct{}{
	SectionEnrichment: emptyStruct,
	SectionEvaluate:   emptyStruct,
	SectionCommunity:  emptyStruct,
}
