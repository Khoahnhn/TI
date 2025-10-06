package utils

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
	"gitlab.viettelcyber.com/awesome-threat/library/udm"
)

func TestInferEntityType(t *testing.T) {
	assert.Equal(t, udm.EntityTypeDomain, InferEntityType("example.com"))
	assert.Equal(t, udm.EntityTypeURL, InferEntityType("https://example.com"))
	assert.Equal(t, udm.EntityTypeIPAddress, InferEntityType("8.8.8.8"))
	assert.Equal(t, udm.EntityTypeIPAddress, InferEntityType("2001:4860:4860::8888"))
	assert.Equal(t, udm.EntityTypeFile, InferEntityType(hash.SHA1("test")))
	assert.Equal(t, udm.EntityType(""), InferEntityType(""))
}

func TestIPToInt(t *testing.T) {
	assert.Equal(t, big.NewInt(16777216), IPToInt("1.0.0.0", udm.IPTypeIPv4))
}

func TestIsCVE(t *testing.T) {
	assert.True(t, IsCVE("CVE-1000-2000"))
	assert.False(t, IsCVE("not cve"))
}

func TestIsPrivateIP(t *testing.T) {
	assert.True(t, IsPrivateIP("127.0.0.1"))
	assert.False(t, IsPrivateIP("8.8.8.8"))
}
