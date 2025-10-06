package udm

type File struct {
	Authentihash         string   `json:"authentihash,omitempty"`
	CapabilitiesTags     []string `json:"capabilities_tags,omitempty"`
	EmbeddedDomains      []string `json:"embedded_domains,omitempty"`
	EmbeddedIPs          []string `json:"embedded_ips,omitempty"`
	EmbeddedURLs         []string `json:"embedded_urls,omitempty"`
	FirstSeenTime        int64    `json:"first_seen_time,omitempty"`
	FirstSubmissionTime  int64    `json:"first_submission_time,omitempty"`
	Filename             string   `json:"filename,omitempty"`
	FullPath             string   `json:"full_path,omitempty"`
	LastAnalysisTime     int64    `json:"last_analysis_time,omitempty"`
	LastModificationTime int64    `json:"last_modification_time,omitempty"`
	LastSeenTime         int64    `json:"last_seen_time,omitempty"`
	LastSubmissionTime   int64    `json:"last_submission_time,omitempty"`
	MD5                  string   `json:"md5,omitempty"`
	SHA1                 string   `json:"sha1,omitempty"`
	SHA256               string   `json:"sha256,omitempty"`
	SHA512               string   `json:"sha512,omitempty"`
	MIMEType             string   `json:"mime_type,omitempty"`
	Size                 int64    `json:"size,omitempty"`
	SSDeep               string   `json:"ssdeep,omitempty"`
	StatDev              int64    `json:"stat_dev,omitempty"`
	StatFlags            int64    `json:"stat_flags,omitempty"`
	StatInode            int64    `json:"stat_inode,omitempty"`
	StatNlink            int64    `json:"stat_nlink,omitempty"`
	VHash                string   `json:"vhash,omitempty"`
}
