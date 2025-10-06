package virustotal

type (
	SSLCertificate struct {
		CertSignature      *CertSignature         `json:"cert_signature"`
		Extensions         map[string]interface{} `json:"extensions"`
		Issuer             *DistinguishedName     `json:"issuer"`
		PublicKey          *PublicKey             `json:"public_key"`
		SerialNumber       string                 `json:"serial_number"`
		SignatureAlgorithm string                 `json:"signature_algorithm"`
		Size               int                    `json:"size"`
		Subject            *DistinguishedName     `json:"subject"`
		Thumbprint         string                 `json:"thumbprint"`
		ThumbprintSHA256   string                 `json:"thumbprint_sha256"`
		Validity           *Validity              `json:"validity"`
		Version            string                 `json:"version"`
	}

	CertSignature struct {
		Signature          string `json:"signature"`
		SignatureAlgorithm string `json:"signature_algorithm"`
	}

	DistinguishedName struct {
		CountryName         string `json:"C,omitempty"`
		CommonName          string `json:"CN,omitempty"`
		Locality            string `json:"L,omitempty"`
		Organization        string `json:"O,omitempty"`
		OrganizationalUnit  string `json:"OU,omitempty"`
		StateOrProvinceName string `json:"ST,omitempty"`
	}

	PublicKey struct {
		Algorithm string `json:"algorithm"`
		DSA       *struct {
			P   string `json:"p"`
			Q   string `json:"q"`
			G   string `json:"g"`
			Pub string `json:"pub"`
		} `json:"dsa,omitempty"`
		EC *struct {
			OID string `json:"oid"`
			PUB string `json:"pub"`
		} `json:"ec,omitempty"`
		RSA *struct {
			Exponent string `json:"exponent"`
			KeySize  int    `json:"key_size"`
			Modulus  string `json:"modulus"`
		} `json:"rsa,omitempty"`
	}

	Validity struct {
		NotAfter  string `json:"not_after"`
		NotBefore string `json:"not_before"`
	}
)
