package service

import (
	"context"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

type MailService interface {
	BuildAlertConfig(ctx context.Context, username, groupID string) (*model.AlertConfig, error)
	SendWelcomeEmail(recipients []string, title, templateName string, data map[string]interface{}) error
	GetDefaultEmbeds(lang string) map[string][]byte
	GetCreateAccountBanner(lang string) map[string][]byte
	SendEmailByAPI(
		receivers []string,
		subject string,
		content string,
		embeds map[string][]byte,
		attachments map[string][]byte,
	) error
}
