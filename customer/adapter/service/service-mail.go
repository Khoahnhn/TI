package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/templates"

	"github.com/flosch/pongo2/v6"
)

type alertService struct {
	userSettingRepo mongo.UserSettingRepository
	scheduleRepo    mongo.ScheduleRepository
	accountRepo     mongo.AccountRepository
	config          *model.MailConfig
	templatePath    string
	client          *resty.Client
}

func (s *alertService) SendEmailByAPI(
	receivers []string,
	subject string,
	content string,
	embeds map[string][]byte,
	attachments map[string][]byte,
) error {
	mailAddress := strings.Join(receivers, ",")
	payload := map[string]string{
		"bcc":          mailAddress,
		"subject":      subject,
		"body":         content,
		"no_signature": "true",
	}
	request := s.client.R().SetFormData(payload)
	for filename, fileData := range embeds {
		request = request.SetFileReader("embed", filename, bytes.NewReader(fileData))
	}
	// Add attachments (nếu có)
	for filename, data := range attachments {
		request.SetFileReader("attachment", filename, bytes.NewReader(data))
	}
	res, err := request.Post(s.config.MailAPI)
	if err != nil {
		return fmt.Errorf("failed to send mail: %w", err)
	}
	if res.StatusCode() != http.StatusOK {
		return fmt.Errorf("mail API returned status %d: %s, receivers: %v", res.StatusCode(), res.String(), mailAddress)
	}
	return nil
}

func (s *alertService) GetCreateAccountBanner(lang string) map[string][]byte {
	banners := make(map[string][]byte)
	switch lang {
	case "vi":
		banners["BG_Top.png"] = []byte(base64.StdEncoding.EncodeToString([]byte(templates.ImgTopVi)))
	default:
		banners["BG_Top.png"] = []byte(base64.StdEncoding.EncodeToString([]byte(templates.ImgTopEn)))
	}

	return banners
}

func (s *alertService) GetDefaultEmbeds(lang string) map[string][]byte {
	embeds := make(map[string][]byte)
	embeds["BG_Signature.png"] = []byte(base64.StdEncoding.EncodeToString([]byte(templates.ImgSignature)))
	embeds["imail.png"] = []byte(base64.StdEncoding.EncodeToString([]byte(templates.ImgImail)))
	embeds["imap.png"] = []byte(base64.StdEncoding.EncodeToString([]byte(templates.ImgImap)))
	embeds["iphone.png"] = []byte(base64.StdEncoding.EncodeToString([]byte(templates.ImgIphone)))
	embeds["iweb.png"] = []byte(base64.StdEncoding.EncodeToString([]byte(templates.ImgIweb)))
	switch lang {
	case "vi":
		embeds["BG_Bottom.png"] = []byte(base64.StdEncoding.EncodeToString([]byte(templates.ImgBottomVi)))
	default:
		embeds["BG_Bottom.png"] = []byte(base64.StdEncoding.EncodeToString([]byte(templates.ImgBottomEn)))
	}

	return embeds
}

func (s *alertService) SendWelcomeEmail(recipients []string, title, templateName string, data map[string]interface{}) error {
	// Parse template bằng Pongo2
	templatePath := filepath.Join(s.templatePath, templateName)
	tpl, err := pongo2.FromFile(templatePath)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}
	// Render template
	out, err := tpl.Execute(pongo2.Context{
		"init": data,
	})
	if err != nil {
		return fmt.Errorf("failed to execute template: %v", err)
	}
	var bodyContent bytes.Buffer
	bodyContent.WriteString(out)
	// Lấy ngôn ngữ
	lang := "vi"
	if v, ok := data["language"].(string); ok {
		lang = v
	}
	// Load embeds + banners
	embeds := s.GetDefaultEmbeds(lang)
	banners := s.GetCreateAccountBanner(lang)
	for k, v := range banners {
		embeds[k] = v
	}
	return s.SendEmailByAPI(recipients, title, bodyContent.String(), embeds, nil)
}

func NewAlertService(userSettingRepo mongo.UserSettingRepository, scheduleRepo mongo.ScheduleRepository, accountRepo mongo.AccountRepository,
	cfg *model.MailConfig, templatePatch string) MailService {
	client := resty.New().
		SetRetryCount(3).
		SetRetryWaitTime(2 * time.Second).
		SetRetryMaxWaitTime(10 * time.Second).
		SetTimeout(15 * time.Second)
	return &alertService{
		userSettingRepo: userSettingRepo,
		scheduleRepo:    scheduleRepo,
		accountRepo:     accountRepo,
		config:          cfg,
		templatePath:    templatePatch,
		client:          client,
	}
}

func (s *alertService) BuildAlertConfig(ctx context.Context, username, groupId string) (*model.AlertConfig, error) {
	// Default setting
	defaultSetting, err := s.accountRepo.DefaultSetting().GetDefaultSetting(ctx)
	if err != nil {
		return nil, err
	}
	if defaultSetting == nil {
		return nil, fmt.Errorf("no setting")
	}

	// Lấy thông tin user settings
	userSettings, err := s.userSettingRepo.GetUserSettings(ctx, username)
	if err != nil {
		return nil, err
	}

	// Lấy thông tin schedules
	schedules, err := s.scheduleRepo.GetSchedules(ctx, groupId)
	if err != nil {
		return nil, err
	}

	// Group setting
	groupSettings, err := s.accountRepo.GroupSetting().GetGroupSetting(ctx, groupId)
	if err != nil {
		return nil, err
	}

	// Tạo map để tra cứu permissions từ schedules
	permissionMap := make(map[string]map[defs.SettingAction]bool)
	for _, setting := range userSettings {
		if permissionMap[setting.Name] == nil {
			permissionMap[setting.Name] = make(map[defs.SettingAction]bool)
		}
		for _, action := range setting.Actions {
			actionKey, ok := defaultSetting.Constant.Action.Alert[action.ID]
			if !ok {
				actionKey = defaultSetting.Constant.Action.Report[action.ID]
			}
			permissionMap[setting.Name][defs.SettingAction(actionKey)] = action.Status
		}
	}

	// Tạo map để dễ tra cứu schedules
	scheduleMap := make(map[string][]model.Schedule)
	for _, schedule := range schedules {
		key := schedule.ExtraData.Key
		scheduleMap[key] = append(scheduleMap[key], schedule)
	}

	groupSettingMap := make(map[string]model.GroupSetting)
	for _, setting := range groupSettings {
		groupSettingMap[setting.Name] = setting
	}

	config := &model.AlertConfig{}

	// Vulnerabilities
	config.Vulnerabilities = s.buildAlertSetting("vulnerable", permissionMap, scheduleMap, groupSettingMap)

	// Brand Abuse
	config.BrandAbuse = s.buildAlertSetting("brand", permissionMap, scheduleMap, groupSettingMap)

	// Data Leak
	config.DataLeak = s.buildAlertSetting("data_leak", permissionMap, scheduleMap, groupSettingMap)

	// Compromise
	config.Compromise = s.buildAlertSetting("compromise", permissionMap, scheduleMap, groupSettingMap)

	// Malware
	config.Malware = s.buildAlertSetting("malware", permissionMap, scheduleMap, groupSettingMap)

	// EASM
	config.EASM = s.buildAlertSetting("easm_issue", permissionMap, scheduleMap, groupSettingMap)

	// Report
	config.Report = s.buildReportSetting(permissionMap, groupSettingMap)

	return config, nil
}

func (s *alertService) buildAlertSetting(
	key string,
	permissionMap map[string]map[defs.SettingAction]bool,
	scheduleMap map[string][]model.Schedule,
	groupSettingMap map[string]model.GroupSetting,
) model.AlertSetting {
	enabled := false
	actions, exists := permissionMap[key]
	if !exists {
		return model.AlertSetting{}
	}

	if actions[defs.SettingActionReceiveAlert] {
		enabled = true
	}
	severities := []string{}
	severityPriority := map[defs.SettingAction]int{
		defs.SettingActionReceiveCritical: 4,
		defs.SettingActionReceiveHigh:     3,
		defs.SettingActionReceiveMedium:   2,
		defs.SettingActionReceiveLow:      1,
	}
	for action, enable := range actions {
		if !enable {
			continue
		}
		if severity, ok := defs.SettingActionSeverityMap[action]; ok {
			severities = append(severities, severity)
		}
	}
	sort.Slice(severities, func(i, j int) bool {
		return severityPriority[defs.SettingAction(severities[i])] > severityPriority[defs.SettingAction(severities[j])]
	})

	// Tìm schedule tương ứng
	frequency := "Not set"
	lastScan := "N/A"
	nextScan := "N/A"

	if schedules, exists := scheduleMap[key]; exists && len(schedules) > 0 {
		schedule := schedules[0] // Lấy schedule đầu tiên

		lastScan = schedule.TimeUpdated.Format("15:04:05")
		nextScan = schedule.TimeExecute.Format("15:04:05")
	}

	if groupSetting, ok := groupSettingMap[key]; ok {
		schedule := groupSetting.Schedule[0]
		switch schedule.Type {
		case "minutely":
			frequency = fmt.Sprintf("every %d minutes", schedule.Data.Timedelta)
		case "hourly":
			frequency = fmt.Sprintf("every %d hours", schedule.Data.Timedelta)
		case "daily":
			frequency = fmt.Sprintf("daily at %s", schedule.Data.TimeMoment)
		case "weekly":
			frequency = fmt.Sprintf("weekly on day %d at %s", schedule.Data.DayOfWeek, schedule.Data.TimeMoment)
		case "monthly":
			if schedule.Data.ByDay != nil {
				frequency = fmt.Sprintf("monthly on day %d at %s", schedule.Data.ByDay.DayInMonth, schedule.Data.ByDay.TimeMoment)
			}
		}

	}

	return model.AlertSetting{
		Enabled:   enabled,
		Frequency: frequency,
		LastScan:  lastScan,
		NextScan:  nextScan,
		Severity:  severities,
	}
}

func (s *alertService) buildReportSetting(
	permissionMap map[string]map[defs.SettingAction]bool,
	groupSettingMap map[string]model.GroupSetting,
) model.ReportSetting {
	// Kiểm tra permission cho report
	enabled := false
	if actions, exists := permissionMap["report"]; exists {
		if actions[defs.SettingActionReceiveAlert] {
			enabled = true
		}
	}
	indexOrdinalMap := map[int]string{
		1: "first",
		2: "second",
		3: "third",
		4: "fourth",
		5: "last",
	}

	daily := "Not set"
	weekly := "Not set"
	monthly := "Not set"
	quarterly := "Not set"

	if schedules, exists := groupSettingMap["report"]; exists {
		for _, schedule := range schedules.Schedule {
			switch schedule.Type {
			case "daily":
				daily = fmt.Sprintf("at %s", schedule.Data.TimeMoment)
			case "weekly":
				weekly = fmt.Sprintf("at %s on %s", schedule.Data.TimeMoment, time.Weekday((schedule.Data.DayOfWeek+1)%7))
			case "monthly":
				if schedule.Data.ByWeekDay != nil {
					monthly = fmt.Sprintf("at %s on the %s %s",
						schedule.Data.ByWeekDay.TimeMoment,
						indexOrdinalMap[schedule.Data.ByWeekDay.NWeek+1],
						time.Weekday((schedule.Data.ByWeekDay.DayOfWeek+1)%7),
					)
				} else if schedule.Data.ByDay != nil {
					monthly = fmt.Sprintf("at %s on %s", schedule.Data.ByDay.TimeMoment, ordinal(schedule.Data.ByDay.DayInMonth))
				}
			case "quarterly":
				if schedule.Data.ByNMonthIndex != nil {
					quarterly = fmt.Sprintf("at %s on the %s %s of the %s month",
						schedule.Data.ByNMonthIndex.TimeMoment,
						indexOrdinalMap[schedule.Data.ByNMonthIndex.Index+1],
						time.Weekday((schedule.Data.ByNMonthIndex.DayInWeek+1)%7),
						ordinal(schedule.Data.ByNMonthIndex.NMonth+1),
					)
				} else if schedule.Data.ByNMonthAndDay != nil {
					quarterly = fmt.Sprintf("at %s on the %s of the %s month",
						schedule.Data.ByNMonthAndDay.TimeMoment,
						ordinal(schedule.Data.ByNMonthAndDay.Day),
						indexOrdinalMap[schedule.Data.ByNMonthAndDay.NMonth+1],
					)
				}
			}
		}
	}

	return model.ReportSetting{
		Enabled:   enabled,
		Daily:     daily,
		Weekly:    weekly,
		Monthly:   monthly,
		Quarterly: quarterly,
	}
}

func ordinal(n int) string {
	// handle special cases: 11th, 12th, 13th
	if n%100 >= 11 && n%100 <= 13 {
		return fmt.Sprintf("%dth", n)
	}

	switch n % 10 {
	case 1:
		return fmt.Sprintf("%dst", n)
	case 2:
		return fmt.Sprintf("%dnd", n)
	case 3:
		return fmt.Sprintf("%drd", n)
	default:
		return fmt.Sprintf("%dth", n)
	}
}
