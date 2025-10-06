package udm

type PopularityRank struct {
	Giver         string `json:"giver,omitempty"`
	IngestionTime int64  `json:"ingestion_time,omitempty"`
	Rank          int64  `json:"rank,omitempty"`
}
