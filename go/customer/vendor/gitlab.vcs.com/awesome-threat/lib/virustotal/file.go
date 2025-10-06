package virustotal

type (
	FileV2 struct {
		Vhash               string                 `json:"vhash,omitempty"`
		Authentihash        string                 `json:"authentihash,omitempty"`
		MD5                 string                 `json:"md5,omitempty"`
		SHA1                string                 `json:"sha1,omitempty"`
		SHA256              string                 `json:"sha256,omitempty"`
		CommunityReputation int                    `json:"community_reputation,omitempty"`
		FirstSeen           string                 `json:"first_seen,omitempty"`
		LastSeen            string                 `json:"last_seen,omitempty"`
		Positives           int                    `json:"positives,omitempty"`
		MaliciousVotes      int                    `json:"malicious_votes,omitempty"`
		HarmlessVotes       int                    `json:"harmless_votes,omitempty"`
		Permalink           string                 `json:"permalink,omitempty"`
		Resource            string                 `json:"resource,omitempty"`
		ResponseCode        int                    `json:"response_code,omitempty"`
		ScanDate            string                 `json:"scan_date,omitempty"`
		ScanID              string                 `json:"scan_id,omitempty"`
		Scans               map[string]FileV2Scan  `json:"scans,omitempty"`
		Size                int64                  `json:"size,omitempty"`
		Ssdeep              string                 `json:"ssdeep,omitempty"`
		SubmissionNames     []string               `json:"submission_names,omitempty"`
		Tags                []string               `json:"tags,omitempty"`
		TimesSubmitted      int                    `json:"times_submitted,omitempty"`
		Total               int                    `json:"total,omitempty"`
		Type                string                 `json:"type,omitempty"`
		UniqueSources       int                    `json:"unique_sources,omitempty"`
		VerboseMsg          string                 `json:"verbose_msg,omitempty"`
		AdditionalInfo      map[string]interface{} `json:"additional_info,omitempty"`
	}

	FileV2Scan struct {
		Detected bool   `json:"detected"`
		Result   string `json:"result"`
		Update   string `json:"update"`
		Version  string `json:"version"`
	}

	FileV3 struct {
		ID         string                 `json:"id,omitempty"`
		Type       string                 `json:"type,omitempty"`
		Links      map[string]interface{} `json:"links,omitempty"`
		Attributes *FileV3Attribute       `json:"attributes,omitempty"`
		Error      map[string]interface{} `json:"error,omitempty"`
	}

	FileV3Attribute struct {
		CapabilitiesTags            []string                     `json:"capabilities_tags,omitempty"`
		CreationDate                int64                        `json:"creation_date,omitempty"`
		Downloadable                bool                         `json:"downloadable,omitempty"`
		FirstSubmissionDate         int64                        `json:"first_submission_date,omitempty"`
		LastAnalysisDate            int64                        `json:"last_analysis_date,omitempty"`
		LastAnalysisResults         map[string]*AnalysisResult   `json:"last_analysis_results,omitempty"`
		LastAnalysisStats           *AnalysisStats               `json:"last_analysis_stats,omitempty"`
		LastModificationDate        int64                        `json:"last_modification_date,omitempty"`
		LastSubmissionDate          int64                        `json:"last_submission_date,omitempty"`
		MainIcon                    FileV3MainIcon               `json:"main_icon,omitempty"`
		MD5                         string                       `json:"md5,omitempty"`
		MeaningfulName              string                       `json:"meaningful_name,omitempty"`
		Names                       []string                     `json:"names,omitempty"`
		Reputation                  int                          `json:"reputation,omitempty"`
		SHA1                        string                       `json:"sha1,omitempty"`
		SHA256                      string                       `json:"sha256,omitempty"`
		SigmaAnalysisSummary        map[string]interface{}       `json:"sigma_analysis_summary,omitempty"`
		Size                        int64                        `json:"size,omitempty"`
		Tags                        []string                     `json:"tags,omitempty"`
		TimesSubmitted              int                          `json:"times_submitted,omitempty"`
		Permhash                    string                       `json:"permhash,omitempty"`
		TotalVotes                  FileV3TotalVotes             `json:"total_votes,omitempty"`
		TypeDescription             string                       `json:"type_description,omitempty"`
		TypeExtension               string                       `json:"type_extension,omitempty"`
		TypeTag                     string                       `json:"type_tag,omitempty"`
		TypeTags                    []string                     `json:"type_tags,omitempty"`
		UniqueSources               int                          `json:"unique_sources,omitempty"`
		Vhash                       string                       `json:"vhash,omitempty"`
		CrowdsourceAIResults        *FileV3CrowdsourcedAIResults `json:"crowdsource_ai_results,omitempty"`
		ThreatVerdict               ThreatVerdict                `json:"threat_verdict,omitempty"`
		ThreatSeverity              *FileV3ThreatSeverity        `json:"threat_severity,omitempty"`
		Androguard                  map[string]interface{}       `json:"androguard,omitempty"`
		AsfInfo                     map[string]interface{}       `json:"asf_info,omitempty"`
		Authentihash                string                       `json:"authentihash,omitempty"`
		BundleInfo                  map[string]interface{}       `json:"bundle_info,omitempty"`
		ClassInfo                   map[string]interface{}       `json:"class_info,omitempty"`
		CrowdsourcedIDSResults      []map[string]interface{}     `json:"crowdsourced_ids_results,omitempty"`
		CrowdsourcedIDSStats        map[string]int               `json:"crowdsourced_ids_stats,omitempty"`
		CrowdsourcedYaraResults     []map[string]interface{}     `json:"crowdsourced_yara_results,omitempty"`
		DebInfo                     map[string]interface{}       `json:"deb_info,omitempty"`
		Detectiteasy                map[string]interface{}       `json:"detectiteasy,omitempty"`
		DmsInfo                     map[string]interface{}       `json:"dms_info,omitempty"`
		DotNetAssembly              map[string]interface{}       `json:"dot_net_assembly,omitempty"`
		DotNetGuids                 map[string]interface{}       `json:"dot_net_guids,omitempty"`
		ElfInfo                     map[string]interface{}       `json:"elf_info,omitempty"`
		Exiftool                    map[string]interface{}       `json:"exiftool,omitempty"`
		HTMLInfo                    map[string]interface{}       `json:"html_info,omitempty"`
		ImageCodeInjections         string                       `json:"image_code_injections,omitempty"`
		IpaInfo                     map[string]interface{}       `json:"ipa_info,omitempty"`
		IsoimageInfo                map[string]interface{}       `json:"isoimage_info,omitempty"`
		JarInfo                     map[string]interface{}       `json:"jar_info,omitempty"`
		JavascriptInfo              map[string]interface{}       `json:"javascript_info,omitempty"`
		KnownDistributors           map[string]interface{}       `json:"known_distributors,omitempty"`
		LnkInfo                     map[string]interface{}       `json:"lnk_info,omitempty"`
		MachoInfo                   map[string]interface{}       `json:"macho_info,omitempty"`
		Magic                       string                       `json:"magic,omitempty"`
		MalwareConfig               map[string]interface{}       `json:"malware_config,omitempty"`
		OfficeInfo                  map[string]interface{}       `json:"office_info,omitempty"`
		OpenxmlInfo                 map[string]interface{}       `json:"openxml_info,omitempty"`
		Package                     map[string]interface{}       `json:"package,omitempty"`
		PasswordInfo                map[string]interface{}       `json:"password_info,omitempty"`
		PdfInfo                     map[string]interface{}       `json:"pdf_info,omitempty"`
		PEInfo                      map[string]interface{}       `json:"pe_info,omitempty"`
		PopularThreatClassification map[string]interface{}       `json:"popular_threat_classification,omitempty"`
		PowershellInfo              map[string]interface{}       `json:"powershell_info,omitempty"`
		RombiosInfo                 map[string]interface{}       `json:"rombios_info,omitempty"`
		RftInfo                     map[string]interface{}       `json:"rft_info,omitempty"`
		SandboxVerdicts             map[string]interface{}       `json:"sandbox_verdicts,omitempty"`
		SigmaAnalysisResults        []map[string]interface{}     `json:"sigma_analysis_results,omitempty"`
		SigmaAnalysisStats          map[string]int               `json:"sigma_analysis_stats,omitempty"`
		SignatureInfo               map[string]interface{}       `json:"signature_info,omitempty"`
		Snort                       map[string]interface{}       `json:"snort,omitempty"`
		Suricata                    map[string]interface{}       `json:"suricata,omitempty"`
		Ssdeep                      string                       `json:"ssdeep,omitempty"`
		SwfInfo                     map[string]interface{}       `json:"swf_info,omitempty"`
		Telfhash                    string                       `json:"telfhash,omitempty"`
		Tlsh                        string                       `json:"tlsh,omitempty"`
		TrafficInspection           map[string]interface{}       `json:"traffic_inspection,omitempty"`
		Trid                        []map[string]interface{}     `json:"trid,omitempty"`
		VbaInfo                     map[string]interface{}       `json:"vba_info,omitempty"`
		Wireshark                   map[string]interface{}       `json:"wireshark,omitempty"`
	}

	FileV3MainIcon struct {
		RawMD5 string `json:"raw_md5,omitempty"`
		Dhash  string `json:"dhash,omitempty"`
	}

	FileV3SandboxVerdicts struct {
		Category              string   `json:"category,omitempty"`
		Confidence            int      `json:"confidence,omitempty"`
		MalwareClassification []string `json:"malware_classification,omitempty"`
		MalwareNames          []string `json:"malware_names,omitempty"`
		SandboxName           string   `json:"sandbox_name,omitempty"`
	}

	FileV3TotalVotes struct {
		Harmless  int `json:"harmless,omitempty"`
		Malicious int `json:"malicious,omitempty"`
	}

	FileV3CrowdsourcedAIResults struct {
		Analysis string `json:"analysis,omitempty"`
		Source   string `json:"source,omitempty"`
		ID       string `json:"id,omitempty"`
	}

	FileV3ThreatSeverity struct {
		LastAnalysisDate    int64                  `json:"last_analysis_date,omitempty"`
		ThreatSeverityLevel ThreatSeverityLevel    `json:"threat_severity_level,omitempty"`
		LevelDescription    string                 `json:"level_description,omitempty"`
		Version             int                    `json:"version,omitempty"`
		ThreatSeverityData  map[string]interface{} `json:"threat_severity_data,omitempty"`
	}

	FileBehaviourV3Attribute struct {
		AnalysisDate             int64                    `json:"analysis_date,omitempty"`
		Behash                   string                   `json:"behash,omitempty"`
		CallsHighlighted         []string                 `json:"calls_highlighted,omitempty"`
		CommandExecutions        []string                 `json:"command_executions,omitempty"`
		FilesOpened              []string                 `json:"files_opened,omitempty"`
		FilesWritten             []string                 `json:"files_written,omitempty"`
		FilesDeleted             []string                 `json:"files_deleted,omitempty"`
		FilesAttributeChanged    []string                 `json:"files_attribute_changed,omitempty"`
		HasHTMLReport            bool                     `json:"has_html_report,omitempty"`
		HasEvtx                  bool                     `json:"has_evtx,omitempty"`
		HasMemdump               bool                     `json:"has_memdump,omitempty"`
		HasPcap                  bool                     `json:"has_pcap,omitempty"`
		HostsFile                []string                 `json:"hosts_file,omitempty"`
		IDSAlerts                []map[string]interface{} `json:"ids_alerts,omitempty"`
		ProcessesTerminated      []string                 `json:"processes_terminated,omitempty"`
		ProcessesKilled          []string                 `json:"processes_killed,omitempty"`
		ProcessesInjected        []string                 `json:"processes_injected,omitempty"`
		ServicesOpened           []string                 `json:"services_opened,omitempty"`
		ServiceCreated           []string                 `json:"service_created,omitempty"`
		ServicesStarted          []string                 `json:"services_started,omitempty"`
		ServicesStopped          []string                 `json:"services_stopped,omitempty"`
		ServicesDeleted          []string                 `json:"services_deleted,omitempty"`
		ServicesBound            []string                 `json:"services_bound,omitempty"`
		WindowsSearched          []string                 `json:"windows_searched,omitempty"`
		WindowsHidden            []string                 `json:"windows_hidden,omitempty"`
		MutexesOpened            []string                 `json:"mutexes_opened,omitempty"`
		MutexesCreated           []string                 `json:"mutexes_created,omitempty"`
		SignalsObserved          []string                 `json:"signals_observed,omitempty"`
		Invokes                  []string                 `json:"invokes,omitempty"`
		CryptoAlgorithmsObserved []string                 `json:"crypto_algorithms_observed,omitempty"`
		CryptoKeys               []string                 `json:"crypto_keys,omitempty"`
		CryptoPlainText          []string                 `json:"crypto_plain_text,omitempty"`
		TextDecoded              []string                 `json:"text_decoded,omitempty"`
		TextHighlighted          []string                 `json:"text_highlighted,omitempty"`
		VerdictConfidence        int                      `json:"verdict_confidence,omitempty"`
		Ja3Digests               []string                 `json:"ja3_digests,omitempty"`
		Tls                      []map[string]interface{} `json:"tls,omitempty"`
		SigmaAnalysisResults     []map[string]interface{} `json:"sigma_analysis_results,omitempty"`
		SignatureMatches         []map[string]interface{} `json:"signature_matches,omitempty"`
		MitreAttackTechniques    []map[string]interface{} `json:"mitre_attack_techniques,omitempty"`
		ActivitiesStarted        []string                 `json:"activities_started,omitempty"`
		ContentModelObservers    []string                 `json:"content_model_observers,omitempty"`
		ContentModelSets         []map[string]interface{} `json:"content_model_sets,omitempty"`
		DatabasesDeleted         []string                 `json:"databases_deleted,omitempty"`
		DatabasesOpened          []string                 `json:"databases_opened,omitempty"`
		PermissionsRequested     []map[string]interface{} `json:"permissions_requested,omitempty"`
		SharedPreferencesLookups []string                 `json:"shared_preferences_lookups,omitempty"`
		SharedPreferencesSets    []map[string]interface{} `json:"shared_preferences_sets,omitempty"`
		SignalsHooked            []string                 `json:"signals_hooked,omitempty"`
		SystemPropertyLookups    []string                 `json:"system_property_lookups,omitempty"`
		SystemPropertySets       []map[string]interface{} `json:"system_property_sets,omitempty"`
		ModulesLoaded            []string                 `json:"modules_loaded,omitempty"`
		RegistryKeysOpened       []string                 `json:"registry_keys_opened,omitempty"`
		RegistryKeysSet          []map[string]interface{} `json:"registry_keys_set,omitempty"`
		RegistryKeysDeleted      []string                 `json:"registry_keys_deleted,omitempty"`
	}

	FileBehaviourV3 struct {
		ID         string                    `json:"id,omitempty"`
		Type       string                    `json:"type,omitempty"`
		Links      map[string]interface{}    `json:"links,omitempty"`
		Error      map[string]interface{}    `json:"error,omitempty"`
		Attributes *FileBehaviourV3Attribute `json:"attributes,omitempty"`
	}

	ResponseFileV3 struct {
		Data  *FileV3        `json:"data,omitempty"`
		Links *ResponseLinks `json:"links,omitempty"`
		Meta  *ResponseMeta  `json:"meta,omitempty"`
	}

	ResponseFileV3ExecutionParents struct {
		Data  *FileV3        `json:"data,omitempty"`
		Links *ResponseLinks `json:"links,omitempty"`
		Meta  *ResponseMeta  `json:"meta,omitempty"`
	}

	ResponseFileV3BundledFiles struct {
		Data  *FileV3        `json:"data,omitempty"`
		Links *ResponseLinks `json:"links,omitempty"`
		Meta  *ResponseMeta  `json:"meta,omitempty"`
	}

	ResponseFileV3DroppedFiles struct {
		Data  *FileV3        `json:"data,omitempty"`
		Links *ResponseLinks `json:"links,omitempty"`
		Meta  *ResponseMeta  `json:"meta,omitempty"`
	}

	ResponseFileV3Behaviours struct {
		Data  []*FileBehaviourV3 `json:"data,omitempty"`
		Links *ResponseLinks     `json:"links,omitempty"`
		Meta  *ResponseMeta      `json:"meta,omitempty"`
	}
)
