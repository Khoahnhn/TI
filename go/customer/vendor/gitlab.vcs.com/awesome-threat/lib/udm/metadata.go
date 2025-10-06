package udm

import (
	"fmt"

	"gitlab.viettelcyber.com/awesome-threat/library/hash"
)

type Metadata struct {
	CollectedTimestamp    int64             `json:"collected_timestamp"`
	CreationTimestamp     int64             `json:"creation_timestamp"`
	ModificationTimestamp int64             `json:"modification_timestamp"`
	ValidFromTimestamp    int64             `json:"valid_from_timestamp"`
	ValidToTimestamp      int64             `json:"valid_to_timestamp"`
	EntityType            EntityType        `json:"entity_type"`
	ID                    string            `json:"id"`
	Value                 string            `json:"value"`
	Label                 string            `json:"label"`
	Description           string            `json:"description"`
	Tags                  []string          `json:"tags"`
	Attributes            map[string]string `json:"attributes"`
	VendorName            string            `json:"vendor_name"`
	ProductName           string            `json:"product_name"`
	ProductVersion        string            `json:"product_version"`
	SourceName            string            `json:"source_name"`
	SourceType            SourceType        `json:"source_type"`
}

func (doc *Metadata) GetID() string {
	// Success
	return doc.ID
}

func (doc *Metadata) GenID() {
	// Success
	doc.ID = hash.SHA1(fmt.Sprintf("%s--%s", doc.Value, doc.EntityType))
}
