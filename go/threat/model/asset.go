package model

type (
	Asset struct {
		ID           string `json:"id"`
		Value        string `json:"value"`
		Type         string `json:"type"`
		Status       int    `json:"status"`
		Active       bool   `json:"active"`
		Organization string `json:"organization"`
	}
)

func (doc *Asset) GetID() string {
	// Success
	return doc.ID
}

func (doc *Asset) SetEID(id string) {
	// Success
	doc.ID = id
}
