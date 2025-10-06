package udm

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
)

type (
	SSLCertificate struct {
		ValidateStatus       CertificateValidateStatus           `json:"validate_status,omitempty"`
		CertSignature        *SSLCertificateCertSignature        `json:"cert_signature,omitempty"`
		SubjectPublicKeyInfo *SSLCertificateSubjectPublicKeyInfo `json:"subject_public_key_info,omitempty"`
		FirstSeenTime        int64                               `json:"first_seen_time,omitempty"`
		Issuer               *SSLCertificateSubject              `json:"issuer,omitempty"`
		SerialNumber         string                              `json:"serial_number,omitempty"`
		SignatureAlgorithm   string                              `json:"signature_algorithm,omitempty"`
		Size                 int64                               `json:"size,omitempty"`
		Subject              *SSLCertificateSubject              `json:"subject,omitempty"`
		Thumbprint           string                              `json:"thumbprint,omitempty"`
		ThumbprintSHA256     string                              `json:"thumbprint_sha256,omitempty"`
		Validity             *SSLCertificateValidity             `json:"validity,omitempty"`
		Version              string                              `json:"version,omitempty"`
		TLSVersion           string                              `json:"tls_version,omitempty"`
		Flat                 map[string]interface{}              `json:"flat,omitempty"`
		ScanResult           *SSLCertificateScanResult           `json:"scan_result,omitempty"`
	}

	SSLCertificateCertSignature struct {
		Signature          string `json:"signature,omitempty"`
		SignatureAlgorithm string `json:"signature_algorithm,omitempty"`
	}

	SSLCertificateSubjectPublicKeyInfo struct {
		PublicKeyAlgorithm string                   `json:"public_key_algorithm,omitempty"`
		PublicKey          *SSLCertificatePublicKey `json:"public_key,omitempty"`
	}

	SSLCertificatePublicKey struct {
		RSA   *SSLCertificatePublicKeyRSA   `json:"rsa,omitempty"`
		DSA   *SSLCertificatePublicKeyDSA   `json:"dsa,omitempty"`
		ECDSA *SSLCertificatePublicKeyECDSA `json:"ecdsa,omitempty"`
	}

	SSLCertificatePublicKeyRSA struct {
		Exponent string `json:"exponent,omitempty"`
		KeySize  int    `json:"key_size,omitempty"`
		Modulus  string `json:"modulus,omitempty"`
	}

	SSLCertificatePublicKeyDSA struct {
		P string `json:"p,omitempty"`
		Q string `json:"q,omitempty"`
		G string `json:"g,omitempty"`
		Y string `json:"y,omitempty"`
	}

	SSLCertificatePublicKeyECDSA struct {
		X   string `json:"x,omitempty"`
		Y   string `json:"y,omitempty"`
		OID string `json:"oid,omitempty"`
		Pub string `json:"pub,omitempty"`
	}

	SSLCertificateSubject struct {
		CommonName          string `json:"common_name,omitempty"`
		CountryName         string `json:"country_name,omitempty"`
		Locality            string `json:"locality,omitempty"`
		Organization        string `json:"organization,omitempty"`
		OrganizationalUnit  string `json:"organizational_unit,omitempty"`
		StateOrProvinceName string `json:"state_or_province_name,omitempty"`
	}

	SSLCertificateValidity struct {
		ExpiryTime int64 `json:"expiry_time,omitempty"`
		IssueTime  int64 `json:"issue_time,omitempty"`
	}

	SSLCertificateScanResult struct {
		HTTPSNotDetected        bool `json:"https_not_detected"`
		CertificateExpiryTime   bool `json:"certificate_expiry_time"`
		CertificateIssueTime    bool `json:"certificate_issue_time"`
		CertificateSubject      bool `json:"certificate_subject"`
		EncryptionHashAlgorithm bool `json:"encryption_hash_algorithm"`
		EncryptionProtocol      bool `json:"encryption_protocol"`
	}
)

func (inst *SSLCertificate) Flatten() map[string]interface{} {
	flattened := make(map[string]interface{})
	if value, ok := MappingCertificateValidateStatus[inst.ValidateStatus]; ok {
		flattened["Validate Status"] = value
	} else {
		flattened["Validate Status"] = MappingCertificateValidateStatus[CertificateValidateStatusUnspecified]
	}
	flattened["Version"] = inst.Version
	flattened["Size"] = strconv.Itoa(int(inst.Size))
	flattened["Serial Number"] = inst.SerialNumber
	flattened["Thumbprint"] = inst.Thumbprint
	flattened["Thumbprint SHA256"] = inst.ThumbprintSHA256
	flattened["Signature Algorithm"] = inst.SignatureAlgorithm
	flattened["Issue Time"] = ""
	flattened["Expiry Time"] = ""
	if inst.Validity != nil {
		if inst.Validity.IssueTime > 0 {
			tm, _ := clock.ParseMilliTimestamp(inst.Validity.IssueTime, clock.Local)
			flattened["Issue Time"] = clock.Format(tm, clock.FormatRFC3339CZ)
		}
		if inst.Validity.ExpiryTime > 0 {
			tm, _ := clock.ParseMilliTimestamp(inst.Validity.ExpiryTime, clock.Local)
			flattened["Expiry Time"] = clock.Format(tm, clock.FormatRFC3339CZ)
		}
	}
	if inst.Issuer != nil {
		if inst.Issuer.CommonName != "" {
			flattened["Issuer Common Name (CN)"] = inst.Issuer.CommonName
		}
		if inst.Issuer.CountryName != "" {
			flattened["Issuer Country (C)"] = inst.Issuer.CountryName
		}
		if inst.Issuer.Locality != "" {
			flattened["Issuer Locality (L)"] = inst.Issuer.Locality
		}
		if inst.Issuer.Organization != "" {
			flattened["Issuer Organization (O)"] = inst.Issuer.Organization
		}
		if inst.Issuer.OrganizationalUnit != "" {
			flattened["Issuer Organization (OU)"] = inst.Issuer.OrganizationalUnit
		}
		if inst.Issuer.StateOrProvinceName != "" {
			flattened["Issuer State Or Province Name (ST)"] = inst.Issuer.StateOrProvinceName
		}
	}
	if inst.Subject != nil {
		if inst.Subject.CommonName != "" {
			flattened["Subject Common Name (CN)"] = inst.Subject.CommonName
		}
		if inst.Subject.CountryName != "" {
			flattened["Subject Country (C)"] = inst.Subject.CountryName
		}
		if inst.Subject.Locality != "" {
			flattened["Subject Locality (L)"] = inst.Subject.Locality
		}
		if inst.Subject.Organization != "" {
			flattened["Subject Organization (O)"] = inst.Subject.Organization
		}
		if inst.Subject.OrganizationalUnit != "" {
			flattened["Subject Organization (OU)"] = inst.Subject.OrganizationalUnit
		}
		if inst.Subject.StateOrProvinceName != "" {
			flattened["Subject State Or Province Name (ST)"] = inst.Subject.StateOrProvinceName
		}
	}
	if inst.SubjectPublicKeyInfo != nil {
		if inst.SubjectPublicKeyInfo.PublicKeyAlgorithm != "" {
			flattened["Public Key Algorithm"] = inst.SubjectPublicKeyInfo.PublicKeyAlgorithm
			if inst.SubjectPublicKeyInfo.PublicKey != nil {
				switch inst.SubjectPublicKeyInfo.PublicKeyAlgorithm {
				case "RSA":
					if inst.SubjectPublicKeyInfo.PublicKey.RSA != nil {
						if inst.SubjectPublicKeyInfo.PublicKey.RSA.Modulus != "" {
							flattened["Public Key Modulus"] = inst.SubjectPublicKeyInfo.PublicKey.RSA.Modulus
						}
						if inst.SubjectPublicKeyInfo.PublicKey.RSA.Exponent != "" {
							flattened["Public Key Exponent"] = inst.SubjectPublicKeyInfo.PublicKey.RSA.Exponent
						}
					}
				case "ECDSA":
					if inst.SubjectPublicKeyInfo.PublicKey.ECDSA != nil {
						if inst.SubjectPublicKeyInfo.PublicKey.ECDSA.OID != "" {
							flattened["Public Key OID"] = inst.SubjectPublicKeyInfo.PublicKey.ECDSA.OID
						}
						if inst.SubjectPublicKeyInfo.PublicKey.ECDSA.Pub != "" {
							flattened["Public Key Pub"] = inst.SubjectPublicKeyInfo.PublicKey.ECDSA.Pub
						}
					}
				}
			}
		}
	}
	// Success
	return flattened
}

func (inst *SSLCertificate) Scan(root string) {
	inst.ScanResult = &SSLCertificateScanResult{}
	if inst.Version == "" {
		inst.ScanResult.HTTPSNotDetected = true
		return
	}
	now, _ := clock.Now(clock.Local)
	nowTs := clock.UnixMilli(now)
	// Certificate Expiry Time & Certificate Issue Time
	if inst.Validity != nil {
		if inst.Validity.ExpiryTime < nowTs {
			inst.ScanResult.CertificateExpiryTime = true
		}
		if inst.Validity.IssueTime > nowTs {
			inst.ScanResult.CertificateIssueTime = true
		}
	} else {
		inst.ScanResult.CertificateExpiryTime = true
		inst.ScanResult.CertificateIssueTime = true
	}
	// Certificate Subject
	subject := inst.Subject.CommonName
	if strings.HasPrefix(subject, "*.") {
		subject = strings.TrimLeft(subject, "*.")
	}
	reg := regexp.MustCompile(fmt.Sprintf("^(.*?\\.|)%s$", strings.ReplaceAll(root, ".", "\\.")))
	if !reg.MatchString(subject) {
		inst.ScanResult.CertificateSubject = true
	}
	// Encryption Hash Algorithm
	signatureAlgorithm := strings.ToLower(inst.CertSignature.SignatureAlgorithm)
	if strings.HasPrefix(signatureAlgorithm, hash.AlgorithmMD2) || strings.HasPrefix(signatureAlgorithm, hash.AlgorithmMD4) || strings.HasPrefix(signatureAlgorithm, hash.AlgorithmMD5) || strings.HasPrefix(signatureAlgorithm, hash.AlgorithmSHA1) {
		inst.ScanResult.EncryptionHashAlgorithm = true
	}
	// Encryption Protocol
	if inst.TLSVersion != TLSVersion12 && inst.TLSVersion != TLSVersion13 {
		inst.ScanResult.EncryptionProtocol = true
	}
}

func (inst *SSLCertificate) ScanSummary() []string {
	summaries := make([]string, 0)
	if inst.ScanResult != nil {
		if inst.ScanResult.CertificateSubject {
			summaries = append(summaries, fmt.Sprintf("Wrong Certificate Subject (%s)", inst.Subject.CommonName))
		}
		if inst.ScanResult.CertificateIssueTime {
			issueTime, _ := clock.ParseMilliTimestamp(inst.Validity.IssueTime, clock.Local)
			summaries = append(summaries, fmt.Sprintf("Wrong Issue Time (%s)", clock.Format(issueTime, clock.FormatHuman)))
		}
		if inst.ScanResult.CertificateExpiryTime {
			expiryTime, _ := clock.ParseMilliTimestamp(inst.Validity.ExpiryTime, clock.Local)
			summaries = append(summaries, fmt.Sprintf("Certificate Expiration Date (%s)", clock.Format(expiryTime, clock.FormatHuman)))
		}
		if inst.ScanResult.EncryptionHashAlgorithm {
			summaries = append(summaries, fmt.Sprintf("Weak Encryption Hash Algorithm (%s)", inst.CertSignature.SignatureAlgorithm))
		}
		if inst.ScanResult.EncryptionProtocol {
			if inst.TLSVersion != "" {
				summaries = append(summaries, fmt.Sprintf("Weak Encryption Protocol (%s)", inst.TLSVersion))
			} else {
				summaries = append(summaries, "Weak Encryption Protocol")
			}
		}
		if inst.ScanResult.HTTPSNotDetected {
			summaries = append(summaries, "HTTPS Not Detected")
		}
	}
	// Success
	return summaries
}
