package udm

import "math/big"

type IP struct {
	IP       string   `json:"ip,omitempty"`
	IPNumber *big.Int `json:"ip_number,omitempty"`
	Type     IPType   `json:"type,omitempty"`
}
