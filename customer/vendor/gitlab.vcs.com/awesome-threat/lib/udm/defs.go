package udm

type (
	EntityType                string
	IPType                    string
	RelationshipType          string
	HTTPMethod                string
	SourceType                int
	Directionality            int
	ThreatStatus              int
	Priority                  int
	Confidence                int
	Severity                  int
	VerdictType               int
	PermissionType            int
	CertificateValidateStatus int
)

const (
	Model                                           = "udm"
	DefaultSourceName                               = "vti"
	DefaultVendorName                               = "vcs"
	DefaultProductName                              = "ti"
	DefaultProductVersion                           = "v1.0.0"
	IndexUDM                                        = "udm-%s"
	IPTypeIPv6                     IPType           = "ipv6"
	IPTypeIPv4                     IPType           = "ipv4"
	RelationshipTypeWhois          RelationshipType = "whois"
	RelationshipTypeArtifact       RelationshipType = "artifact"
	RelationshipTypePopularityRank RelationshipType = "popularity_rank"
	RelationshipTypeCertificate    RelationshipType = "certificate"
	RelationshipTypeSSLCertificate RelationshipType = "ssl_certificate"
	RelationshipTypePermission     RelationshipType = "permission"
	RelationshipTypeDNSRecord      RelationshipType = "dns_record"
	RelationshipTypeSecurityResult RelationshipType = "security_result"
	RelationshipTypeVerdictInfo    RelationshipType = "verdict_info"
	RelationshipTypeResolution     RelationshipType = "resolution"
	RelationshipTypeSibling        RelationshipType = "sibling"
	RelationshipTypeNavigate       RelationshipType = "navigate"
	RelationshipTypeHTTPRequest    RelationshipType = "http_request"
)

const (
	EntityTypeIPAddress      EntityType = "ip"
	EntityTypeFile           EntityType = "file"
	EntityTypeDomain         EntityType = "domain"
	EntityTypeURL            EntityType = "url"
	EntityTypePopularityRank EntityType = "popularity_rank"
	EntityTypeUser           EntityType = "user"
	EntityTypeWhois          EntityType = "whois"
	EntityTypeArtifact       EntityType = "artifact"
	EntityTypeSSLCertificate EntityType = "ssl_certificate"
	EntityTypeEmail          EntityType = "email"
	EntityTypePermission     EntityType = "permission"
	EntityTypeRegistry       EntityType = "registry"
	EntityTypeSecurityResult EntityType = "security_result"
	EntityTypeVerdictInfo    EntityType = "verdict_info"
	EntityTypeRelationship   EntityType = "relationship"
	EntityTypeDNSRecord      EntityType = "dns_record"
	EntityTypeHTTPRequest    EntityType = "http_request"
)

const (
	SourceTypeUnspecified SourceType = iota
	SourceTypeEntityContext
	SourceTypeDerivedContext
	SourceTypeGlobalContext
)

const (
	DirectionalityUnspecified Directionality = iota
	Bidirectional
	Unidirectional
)

const (
	ThreatStatusUnspecified ThreatStatus = iota
	ThreatStatusMalicious
	ThreatStatusSuspicious
	ThreatStatusClean
)

const (
	PriorityUnknown Priority = iota
	PriorityLow
	PriorityMedium
	PriorityHigh
)

const (
	ConfidenceUnknown Confidence = iota
	ConfidenceLow
	ConfidenceMedium
	ConfidenceHigh
)

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

const (
	VerdictTypeUnspecified VerdictType = iota
	VerdictTypeProviderML
	VerdictTypeAnalyst
)

const (
	PermissionUnspecified PermissionType = iota
	PermissionAdminWrite
	PermissionAdminRead
	PermissionDataWrite
	PermissionDataRead
)

const (
	HTTPMethodGET     HTTPMethod = "GET"
	HTTPMethodPUT     HTTPMethod = "PUT"
	HTTPMethodPOST    HTTPMethod = "POST"
	HTTPMethodDELETE  HTTPMethod = "DELETE"
	HTTPMethodPATCH   HTTPMethod = "PATCH"
	HTTPMethodHEAD    HTTPMethod = "HEAD"
	HTTPMethodOPTIONS HTTPMethod = "OPTIONS"
	HTTPMethodTRACE   HTTPMethod = "TRACE"
)

const (
	CertificateValidateStatusUnspecified CertificateValidateStatus = iota
	CertificateValidateStatusTrust
	CertificateValidateStatusUnTrust
)

const (
	TLSVersion10 = "TLS 1.0"
	TLSVersion11 = "TLS 1.1"
	TLSVersion12 = "TLS 1.2"
	TLSVersion13 = "TLS 1.3"
	SSLVersion3  = "SSLv3"
)

var (
	MappingCertificateValidateStatus = map[CertificateValidateStatus]string{
		CertificateValidateStatusUnspecified: "Unknown",
		CertificateValidateStatusTrust:       "Trust",
		CertificateValidateStatusUnTrust:     "Untrust",
	}
)
