package defs

const (
	CustomerActive           = "active"
	CustomerInactive         = "inactive"
	CustomerTypeAll          = "all"
	CustomerTypeOrganization = "organization"
	CustomerTypeIndustry     = "industry"
	PackageTypeMass          = "mass"
)

var (
	MappingCustomerActive = map[string]bool{
		CustomerActive:   true,
		CustomerInactive: false,
	}

	EnumCustomerType = []string{
		CustomerTypeAll,
		CustomerTypeOrganization,
		CustomerTypeIndustry,
	}
)

type HistoryEvent string

const (
	HistoryEventCreate               HistoryEvent = "create"
	HistoryEventUpdate               HistoryEvent = "update"
	HistoryEventChangeStatus         HistoryEvent = "change_status"
	HistoryEventChangeActiveStatus   HistoryEvent = "change_active_status"
	HistoryEventChangeInactiveStatus HistoryEvent = "change_inactive_status"
)

type UserStatus bool

const (
	UserStatusActive   UserStatus = true
	UserStatusInactive UserStatus = false
)

type Language string

const (
	LanguageVietnamese Language = "vi"
	LanguageEnglish    Language = "en"
	LanguageJapanese   Language = "jp"
)

var LangList = []Language{LanguageVietnamese, LanguageEnglish, LanguageJapanese}

const PermissionPremium = "api_premium"

type PositionJob struct {
	Key   int    `json:"key"`
	Value string `json:"value"`
}

var MAP_POSITION_JOB = []PositionJob{
	{Key: 1, Value: "Chief Information Security Officer"},
	{Key: 2, Value: "Security Systems Administrator"},
	{Key: 3, Value: "IT Security Engineer"},
	{Key: 4, Value: "Threat Researcher"},
	{Key: 5, Value: "Other"},
	{Key: 6, Value: "Chief Technology Officer"},
}

var MAP_COUNTRY_PUBLIC = []string{
	"Afghanistan", "Albania", "Algeria", "American Samoa", "Andorra", "Angola", "Anguilla", "Antarctica",
	"Antigua and Barbuda", "Argentina", "Armenia", "Aruba", "Australia", "Austria", "Azerbaijan", "Bahamas",
	"Bahrain", "Bangladesh", "Barbados", "Belarus", "Belgium", "Belize", "Benin", "Bermuda", "Bhutan", "Bolivia",
	"Bosnia and Herzegowina", "Botswana", "Bouvet Island", "Brazil", "British Indian Ocean Territory", "Brunei Darussalam",
	"Bulgaria", "Burkina Faso", "Burundi", "Cambodia", "Cameroon", "Canada", "Cape Verde", "Cayman Islands",
	"Central African Republic", "Chad", "Chile", "China", "Christmas Island", "Cocos (Keeling) Islands", "Colombia",
	"Comoros", "Congo", "Congo, the Democratic Republic of the", "Cook Islands", "Costa Rica", "Cote d'Ivoire", "" +
		"Croatia (Hrvatska)", "Cuba", "Cyprus", "Czech Republic", "Denmark", "Djibouti", "Dominica", "Dominican Republic",
	"East Timor", "Ecuador", "Egypt", "El Salvador", "Equatorial Guinea", "Eritrea", "Estonia", "Ethiopia",
	"Falkland Islands (Malvinas)", "Faroe Islands", "Fiji", "Finland", "France", "France Metropolitan",
	"French Guiana", "French Polynesia", "French Southern Territories", "Gabon", "Gambia", "Georgia", "Germany",
	"Ghana", "Gibraltar", "Greece", "Greenland", "Grenada", "Guadeloupe", "Guam", "Guatemala", "Guinea",
	"Guinea-Bissau", "Guyana", "Haiti", "Heard and Mc Donald Islands", "Holy See (Vatican City State)",
	"Honduras", "Hong Kong", "Hungary", "Iceland", "India", "Indonesia", "Iran (Islamic Republic of)",
	"Iraq", "Ireland", "Israel", "Italy", "Jamaica", "Japan", "Jordan", "Kazakhstan", "Kenya", "Kiribati",
	"Korea, Democratic People's Republic of", "Korea, Republic of", "Kuwait", "Kyrgyzstan",
	"Lao, People's Democratic Republic", "Latvia", "Lebanon", "Lesotho", "Liberia", "Libyan Arab Jamahiriya",
	"Liechtenstein", "Lithuania", "Luxembourg", "Macau", "Macedonia, The Former Yugoslav Republic of", "Madagascar",
	"Malawi", "Malaysia", "Maldives", "Mali", "Malta", "Marshall Islands", "Martinique", "Mauritania", "Mauritius",
	"Mayotte", "Mexico", "Micronesia, Federated States of", "Moldova, Republic of", "Monaco", "Mongolia", "Montserrat",
	"Morocco", "Mozambique", "Myanmar", "Namibia", "Nauru", "Nepal", "Netherlands", "Netherlands Antilles",
	"New Caledonia", "New Zealand", "Nicaragua", "Niger", "Nigeria", "Niue", "Norfolk Island",
	"Northern Mariana Islands", "Norway", "Oman", "Pakistan", "Palau", "Panama", "Papua New Guinea", "Paraguay",
	"Peru", "Philippines", "Pitcairn", "Poland", "Portugal", "Puerto Rico", "Qatar", "Reunion", "Romania",
	"Russian Federation", "Rwanda", "Saint Kitts and Nevis", "Saint Lucia", "Saint Vincent and the Grenadines",
	"Samoa", "San Marino", "Sao Tome and Principe", "Saudi Arabia", "Senegal", "Seychelles", "Sierra Leone",
	"Singapore", "Slovakia (Slovak Republic)", "Slovenia", "Solomon Islands", "Somalia", "South Africa",
	"South Georgia and the South Sandwich Islands", "Spain", "Sri Lanka", "St. Helena", "St. Pierre and Miquelon",
	"Sudan", "Suriname", "Svalbard and Jan Mayen Islands", "Swaziland", "Sweden", "Switzerland",
	"Syrian Arab Republic", "Taiwan, Province of China", "Tajikistan", "Tanzania, United Republic of",
	"Thailand", "Togo", "Tokelau", "Tonga", "Trinidad and Tobago", "Tunisia", "Turkey", "Turkmenistan",
	"Turks and Caicos Islands", "Tuvalu", "Uganda", "Ukraine", "United Arab Emirates", "United Kingdom",
	"United States", "United States Minor Outlying Islands", "Uruguay", "Uzbekistan", "Vanuatu", "Venezuela",
	"Vietnam", "Virgin Islands (British)", "Virgin Islands (U.S.)", "Wallis and Futuna Islands", "Western Sahara",
	"Yemen", "Yugoslavia", "Zambia", "Zimbabwe",
}

var MailListPersonal = []string{
	"gmail.com", "yahoo.com", "hotmail.com", "aol.com", "hotmail.co.uk",
	"hotmail.fr", "msn.com", "yahoo.fr", "wanadoo.fr", "orange.fr",
	"comcast.net", "yahoo.co.uk", "yahoo.com.br", "yahoo.co.in", "live.com",
	"rediffmail.com", "free.fr", "gmx.de", "web.de", "yandex.ru",
	"ymail.com", "libero.it", "outlook.com", "uol.com.br", "bol.com.br",
	"mail.ru", "cox.net", "hotmail.it", "sbcglobal.net", "sfr.fr",
	"live.fr", "verizon.net", "live.co.uk", "googlemail.com", "yahoo.es",
	"ig.com.br", "live.nl", "bigpond.com", "terra.com.br", "yahoo.it",
	"neuf.fr", "yahoo.de", "alice.it", "rocketmail.com", "att.net",
	"laposte.net", "facebook.com", "bellsouth.net", "yahoo.in", "hotmail.es",
	"charter.net", "yahoo.ca", "yahoo.com.au", "rambler.ru", "hotmail.de",
	"tiscali.it", "shaw.ca", "yahoo.co.jp", "sky.com", "earthlink.net",
	"optonline.net", "freenet.de", "t-online.de", "aliceadsl.fr", "virgilio.it",
	"home.nl", "qq.com", "telenet.be", "me.com", "yahoo.com.ar",
	"tiscali.co.uk", "yahoo.com.mx", "voila.fr", "gmx.net", "mail.com",
	"planet.nl", "tin.it", "live.it", "ntlworld.com", "arcor.de",
	"yahoo.co.id", "frontiernet.net", "hetnet.nl", "live.com.au", "yahoo.com.sg",
	"zonnet.nl", "club-internet.fr", "juno.com", "optusnet.com.au", "blueyonder.co.uk",
	"bluewin.ch", "skynet.be", "sympatico.ca", "windstream.net", "mac.com",
	"centurytel.net", "chello.nl", "live.ca", "aim.com", "bigpond.net.au",
}

var UserCompKeys = []string{
	"username",
	"phone",
	"first_name",
	"last_name",
	"country",
	"language",
	"title_job",
	"group_id",
	"status",
	"ownership",
	"mfa_properties",
	"api_key",
	"api_key_expired_time",
	"api_key_updated_time",
}
