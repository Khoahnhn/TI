package udm

type Email struct {
	BCC           []string `json:"bcc,omitempty"`
	BounceAddress string   `json:"bounce_address,omitempty"`
	CC            []string `json:"cc,omitempty"`
	From          string   `json:"from,omitempty"`
	MailID        string   `json:"mail_id,omitempty"`
	ReplyTo       string   `json:"reply_to,omitempty"`
	Subject       []string `json:"subject,omitempty"`
	To            []string `json:"to,omitempty"`
}
