package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/360EntSecGroup-Skylar/excelize/v2"
	"github.com/go-resty/resty/v2"
	"github.com/labstack/echo/v4"
	"github.com/panjf2000/ants/v2"
	es "gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/awesome-threat/library/slice"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/adapter/elastic"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/multilang"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/utils/search"
)

type TTIHandler struct {
	pool    *ants.PoolWithFunc
	search  *search.ParserService
	elastic elastic.GlobalRepository
	mongo   mongo.GlobalRepository
	config  model.Config
}

func NewTTIHandler(conf model.Config) TTIHandlerInterface {
	handler := &TTIHandler{
		elastic: elastic.NewGlobalRepository(conf.Connector.Elastic),
		mongo:   mongo.NewGlobalRepository(conf.Connector.Mongo),
		search:  search.NewSearchService("es"),
		config:  conf,
	}
	handler.pool = handler.newTTIAlertPool()
	if handler.config.Api.Timeout == 0 {
		handler.config.Api.Timeout = defs.DefaultTimeout
	}
	// Success
	return handler
}

func (h *TTIHandler) Export(c echo.Context) error {
	body, err := h.verifyAlertExport(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Body(err.Error()).Go()
	}
	// Collect
	file, _ := excelize.OpenFile(defs.DefaultTTIAlertExport)
	// Support
	if slice.String(body.Export).Contains(defs.ExportTTISupport) {
		// Render
		h.renderMultilangTTISupport(file, body.Lang)
		// Start
		supportResults, err := h.mongo.Account().Support().FindAll(body.PrepareTTISupportRequest(), []string{"+creation_time"})
		if err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		supportSummary := &model.TTISupportSummaryExport{}
		supportDetails := make([]*model.TTISupportDetailExport, 0)
		for _, result := range supportResults {
			result.Created, _ = clock.InTimezone(result.Created, clock.Local)
			result.Updated, _ = clock.InTimezone(result.Updated, clock.Local)
			detail := &model.TTISupportDetailExport{
				Created:  clock.Format(result.Created, clock.FormatHuman),
				Updated:  result.GetCompleteTime(),
				Process:  result.GetProcess(body.Lang),
				Object:   result.GetObject(),
				Category: defs.MappingTTISupportTypeTitle[body.Lang][result.Category],
				Status:   defs.MappingTTISupportStatusTitle[body.Lang][result.Status],
			}
			if detail.Category == "" {
				detail.Category = strings.Title(strings.ToLower(result.Category))
			}
			supportDetails = append(supportDetails, detail)
			// Calculate
			supportSummary.Calculate(*detail)
		}
		// Render
		h.renderTTISupport(file, body.GetSuffix(body.Lang), body.Lang, *supportSummary, supportDetails)
		file.SetSheetName(defs.SheetTTISupport, multilang.Get(body.Lang, multilang.KeySheetTTISupport))
		file.SetActiveSheet(1)
	} else {
		file.DeleteSheet(defs.SheetTTISupport)
	}
	// New Alert
	if slice.String(body.Export).Contains(defs.ExportTTIAlert) {
		// Render
		h.renderMultilangTTIAlert(file, body.Lang)
		// Start
		// Get config
		config, err := h.mongo.Account().Configuration().GetConfig()
		if err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		// Prepare query
		query := body.PrepareTTIAlertRequest()
		if body.Query != "" {
			q := h.search.Query(body.Query)
			if q == nil {
				return rest.JSON(c).Code(rest.StatusBadRequest).Log(errors.New("Query không hợp lệ")).Go()
			}
			query = map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						query,
						q,
					},
				},
			}
		}
		// Start
		alertSummary := &model.TTIAlertSummaryExport{}
		alertDetails := make([]*model.TTIAlertDetailExport, 0)
		for _, target := range body.Targets {
			alertResults, err := h.elastic.Enduser().TTIAlert().FindAll(context.Background(), target, query, []string{"+created_time"})
			if err != nil {
				if err.Error() != es.NotFoundError {
					return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
				}
				continue
			}
			details := make(chan *model.TTIAlertDetailExport, len(alertResults))
			for _, alert := range alertResults {
				requestAlert := &model.PoolAlert{
					Details:       details,
					Target:        target,
					Alert:         *alert,
					Configuration: *config,
					Lang:          body.Lang,
				}
				if err = h.pool.Invoke(requestAlert); err != nil {
					continue
				}
			}
			for i := 0; i < len(alertResults); i++ {
				detail := <-details
				alertDetails = append(alertDetails, detail)
				alertSummary.Calculate(*detail)
			}
		}
		sort.Sort(model.TTIAlertDetailExports(alertDetails))
		// Render
		h.renderTTIAlert(file, body.GetSuffix(body.Lang), body.Lang, *alertSummary, alertDetails)
		file.SetSheetName(defs.SheetTTIAlert, multilang.Get(body.Lang, multilang.KeySheetTTIAlert))
		file.SetActiveSheet(0)
	} else {
		file.DeleteSheet(defs.SheetTTIAlert)
	}
	// Save
	now, _ := clock.Now(clock.Local)
	nowStr := clock.Format(now, clock.FormatRFC3339C)
	nowStr = strings.ReplaceAll(nowStr, "-", "")
	nowStr = strings.ReplaceAll(nowStr, " ", "")
	nowStr = strings.ReplaceAll(nowStr, ":", "")
	filename := fmt.Sprintf(defs.DefaultTTIFileName, nowStr)
	filePath := fmt.Sprintf(defs.DefaultTempFilePath, filename)
	if err = file.SaveAs(filePath); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	defer os.Remove(filePath)
	// Success
	return rest.Attachment(c).Name(filename).Path(filePath).Go()
}

func (h *TTIHandler) Delivery(c echo.Context) error {
	body, err := h.verifyAlertDelivery(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Body(err.Error()).Go()
	}
	// Collect
	file, _ := excelize.OpenFile(defs.DefaultTTIAlertExport)
	// Support
	if slice.String(body.Export).Contains(defs.ExportTTISupport) {
		// Render
		h.renderMultilangTTISupport(file, body.Lang)
		// Start
		supportResults, err := h.mongo.Account().Support().FindAll(body.PrepareTTISupportRequest(), []string{"+creation_time"})
		if err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		supportSummary := &model.TTISupportSummaryExport{}
		supportDetails := make([]*model.TTISupportDetailExport, 0)
		for _, result := range supportResults {
			result.Created, _ = clock.InTimezone(result.Created, clock.Local)
			result.Updated, _ = clock.InTimezone(result.Updated, clock.Local)
			detail := &model.TTISupportDetailExport{
				Created:  clock.Format(result.Created, clock.FormatHuman),
				Updated:  result.GetCompleteTime(),
				Process:  result.GetProcess(body.Lang),
				Object:   result.GetObject(),
				Category: defs.MappingTTISupportTypeTitle[body.Lang][result.Category],
				Status:   defs.MappingTTISupportStatusTitle[body.Lang][result.Status],
			}
			if detail.Category == "" {
				detail.Category = strings.Title(strings.ToLower(result.Category))
			}
			supportDetails = append(supportDetails, detail)
			// Calculate
			supportSummary.Calculate(*detail)
		}
		// Render
		h.renderTTISupport(file, body.GetSuffix(), body.Lang, *supportSummary, supportDetails)
		file.SetSheetName(defs.SheetTTISupport, multilang.Get(body.Lang, multilang.KeySheetTTISupport))
		file.SetActiveSheet(1)
	} else {
		file.DeleteSheet(defs.SheetTTISupport)
	}
	// New Alert
	allow := true
	if slice.String(body.Export).Contains(defs.ExportTTIAlert) {
		// Render
		h.renderMultilangTTIAlert(file, body.Lang)
		// Start
		// Get config
		config, err := h.mongo.Account().Configuration().GetConfig()
		if err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		// Prepare query
		query := body.PrepareTTIAlertRequest()
		if body.Query != "" {
			q := h.search.Query(body.Query)
			if q == nil {
				return rest.JSON(c).Code(rest.StatusBadRequest).Log(errors.New("Query không hợp lệ")).Go()
			}
			query = map[string]interface{}{
				"bool": map[string]interface{}{
					"filter": []interface{}{
						query,
						q,
					},
				},
			}
		}
		// Start
		alertSummary := &model.TTIAlertSummaryExport{}
		alertDetails := make([]*model.TTIAlertDetailExport, 0)
		alertResults, err := h.elastic.Enduser().TTIAlert().FindAll(context.Background(), body.Target, query, []string{"+created_time"})
		if err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			allow = false
		}
		details := make(chan *model.TTIAlertDetailExport, len(alertResults))
		for _, alert := range alertResults {
			requestAlert := &model.PoolAlert{
				Details:       details,
				Target:        body.Target,
				Alert:         *alert,
				Configuration: *config,
				Lang:          body.Lang,
			}
			if err = h.pool.Invoke(requestAlert); err != nil {
				continue
			}
		}
		for i := 0; i < len(alertResults); i++ {
			detail := <-details
			alertDetails = append(alertDetails, detail)
			alertSummary.Calculate(*detail)
		}
		sort.Sort(model.TTIAlertDetailExports(alertDetails))
		// Render
		h.renderTTIAlert(file, body.GetSuffix(), body.Lang, *alertSummary, alertDetails)
		file.SetSheetName(defs.SheetTTIAlert, multilang.Get(body.Lang, multilang.KeySheetTTIAlert))
		file.SetActiveSheet(0)
	} else {
		file.DeleteSheet(defs.SheetTTIAlert)
	}
	// Save
	now, _ := clock.Now(clock.Local)
	nowStr := clock.Format(now, clock.FormatRFC3339C)
	nowStr = strings.ReplaceAll(nowStr, "-", "")
	nowStr = strings.ReplaceAll(nowStr, " ", "")
	nowStr = strings.ReplaceAll(nowStr, ":", "")
	filename := fmt.Sprintf(defs.DefaultTTIFileName, nowStr)
	filePath := fmt.Sprintf(defs.DefaultTempFilePath, filename)
	if err = file.SaveAs(filePath); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	defer os.Remove(filePath)
	// Send mail
	if allow && len(body.To) > 0 {
		customer, err := h.mongo.Account().GroupUser().FindByTenantID(body.Target)
		if err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		data := struct {
			Suffix   string
			Customer string
		}{
			Suffix:   body.GetSuffix(),
			Customer: customer.Name,
		}
		temp, err := template.New(filepath.Base(defs.DefaultReportTemplateWithTarget)).ParseFiles(defs.DefaultReportTemplateWithTarget)
		if err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		var buf bytes.Buffer
		if err = temp.Execute(&buf, data); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		subject := ""
		if h.config.App.Debug {
			subject = fmt.Sprintf(defs.TitleAlertExportDebug, body.GetSuffix())
		} else {
			subject = fmt.Sprintf(defs.TitleAlertExport, body.GetSuffix())
		}
		f, err := ioutil.ReadFile(filePath)
		if err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		client := resty.New()
		client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
		client.SetTimeout(time.Duration(clock.Duration(h.config.Api.Timeout) * clock.Minute))
		payload := map[string]string{
			"subject": subject,
			"addrs":   strings.Join(body.To, ","),
			"body":    buf.String(),
		}
		request, err := client.R().SetFormData(payload).SetFileReader("attachment", filename, bytes.NewReader([]byte(base64.StdEncoding.EncodeToString(f)))).Post(fmt.Sprintf(defs.UriMailSend, h.config.Api.Route.Mail))
		if err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		if request.StatusCode() != rest.StatusOK {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Go()
		}
	}
	// Success
	return rest.Attachment(c).Name(filename).Path(filePath).Go()
}

// noinspection GoErrorStringFormat
func (h *TTIHandler) verifyAlertExport(c echo.Context) (body model.RequestTTIAlertExport, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	// Targets
	if len(body.Targets) == 0 {
		return body, errors.New("Không tìm thấy đối tượng xuất báo cáo")
	}
	targets := make([]string, 0)
	for _, target := range body.Targets {
		targets = append(targets, strings.ToLower(target))
	}
	body.Targets = targets
	if len(body.Export) == 0 {
		return body, errors.New("Không tìm thấy tính năng cần xuất báo cáo")
	}
	for _, export := range body.Export {
		if !slice.String(defs.EnumTTIExport).Contains(export) {
			return body, errors.New("Tính năng cần xuất báo cáo không hợp lệ")
		}
	}
	// Created
	if body.Created.Gte == 0 {
		return body, errors.New("Thời điểm bắt đầu không hợp lệ")
	}
	if body.Created.Lte == 0 {
		return body, errors.New("Thời điểm bắt đầu không hợp lệ")
	}
	if body.Created.Gte >= body.Created.Lte {
		return body, errors.New("Thời điểm bắt đầu không nhỏ hơn thời điểm kết thúc")
	}
	createdGte, _ := clock.ParseMilliTimestamp(body.Created.Gte, clock.Local)
	createdLte, _ := clock.ParseMilliTimestamp(body.Created.Lte, clock.Local)
	if createdGte.AddDate(1, 0, 0).Before(createdLte) {
		return body, errors.New("Khoảng thời gian xuất báo cáo nhiều hơn 1 năm")
	}
	if body.Lang == "" {
		body.Lang = defs.LangVI
	}
	if !slice.String(defs.EnumLanguage).Contains(body.Lang) {
		return body, errors.New("invalid value for parameter <lang>")
	}
	// Success
	return body, nil
}

// noinspection GoErrorStringFormat
func (h *TTIHandler) verifyAlertDelivery(c echo.Context) (body model.RequestTTIAlertDelivery, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	// Targets
	if body.Target == "" {
		return body, errors.New("Không tìm thấy đối tượng xuất báo cáo")
	}
	body.Target = strings.ToLower(body.Target)
	if len(body.Export) == 0 {
		return body, errors.New("Không tìm thấy tính năng cần xuất báo cáo")
	}
	for _, export := range body.Export {
		if !slice.String(defs.EnumTTIExport).Contains(export) {
			return body, errors.New("Tính năng cần xuất báo cáo không hợp lệ")
		}
	}
	// Created
	if body.Created.Gte == 0 {
		return body, errors.New("Thời điểm bắt đầu không hợp lệ")
	}
	if body.Created.Lte == 0 {
		return body, errors.New("Thời điểm bắt đầu không hợp lệ")
	}
	if body.Created.Gte >= body.Created.Lte {
		return body, errors.New("Thời điểm bắt đầu không nhỏ hơn thời điểm kết thúc")
	}
	createdGte, _ := clock.ParseMilliTimestamp(body.Created.Gte, clock.Local)
	createdLte, _ := clock.ParseMilliTimestamp(body.Created.Lte, clock.Local)
	if createdGte.AddDate(1, 0, 0).Before(createdLte) {
		return body, errors.New("Khoảng thời gian xuất báo cáo nhiều hơn 1 năm")
	}
	if body.Lang == "" {
		body.Lang = defs.LangVI
	}
	if !slice.String(defs.EnumLanguage).Contains(body.Lang) {
		return body, errors.New("invalid value for parameter <lang>")
	}
	// Success
	return body, nil
}

func (h *TTIHandler) renderMultilangTTIAlert(file *excelize.File, lang string) {
	_ = file.SetCellValue(defs.SheetTTIAlert, "A3", multilang.Get(lang, multilang.KeySummary))
	_ = file.SetCellValue(defs.SheetTTIAlert, "A4", multilang.Get(lang, multilang.KeySeverity))
	_ = file.SetCellValue(defs.SheetTTIAlert, "B4", multilang.Get(lang, multilang.KeyCritical))
	_ = file.SetCellValue(defs.SheetTTIAlert, "B5", multilang.Get(lang, multilang.KeyHigh))
	_ = file.SetCellValue(defs.SheetTTIAlert, "B6", multilang.Get(lang, multilang.KeyMedium))
	_ = file.SetCellValue(defs.SheetTTIAlert, "B7", multilang.Get(lang, multilang.KeyLow))
	_ = file.SetCellValue(defs.SheetTTIAlert, "A9", multilang.Get(lang, multilang.KeyTitleListAlerts))
	_ = file.SetCellValue(defs.SheetTTIAlert, "A10", multilang.Get(lang, multilang.KeyNo))
	_ = file.SetCellValue(defs.SheetTTIAlert, "B10", multilang.Get(lang, multilang.KeyTime))
	_ = file.SetCellValue(defs.SheetTTIAlert, "C10", multilang.Get(lang, multilang.KeyCategory))
	_ = file.SetCellValue(defs.SheetTTIAlert, "D10", multilang.Get(lang, multilang.KeyTitle))
	_ = file.SetCellValue(defs.SheetTTIAlert, "E10", multilang.Get(lang, multilang.KeyObject))
	_ = file.SetCellValue(defs.SheetTTIAlert, "F10", multilang.Get(lang, multilang.KeySeverity))
	_ = file.SetCellValue(defs.SheetTTIAlert, "G10", multilang.Get(lang, multilang.KeyMessage))
	_ = file.SetCellValue(defs.SheetTTIAlert, "H10", multilang.Get(lang, multilang.KeyLinkAlert))
}

func (h *TTIHandler) renderMultilangTTISupport(file *excelize.File, lang string) {
	_ = file.SetCellValue(defs.SheetTTISupport, "A3", multilang.Get(lang, multilang.KeySummary))
	_ = file.SetCellValue(defs.SheetTTISupport, "A4", multilang.Get(lang, multilang.KeyStatus))
	_ = file.SetCellValue(defs.SheetTTISupport, "B4", multilang.Get(lang, multilang.KeyPending))
	_ = file.SetCellValue(defs.SheetTTISupport, "B5", multilang.Get(lang, multilang.KeyInprogress))
	_ = file.SetCellValue(defs.SheetTTISupport, "B6", multilang.Get(lang, multilang.KeyDone))
	_ = file.SetCellValue(defs.SheetTTISupport, "B7", multilang.Get(lang, multilang.KeyReject))
	_ = file.SetCellValue(defs.SheetTTISupport, "A9", multilang.Get(lang, multilang.KeyTitleListAlerts))
	_ = file.SetCellValue(defs.SheetTTISupport, "A10", multilang.Get(lang, multilang.KeyNo))
	_ = file.SetCellValue(defs.SheetTTISupport, "B10", multilang.Get(lang, multilang.KeyRequestTime))
	_ = file.SetCellValue(defs.SheetTTISupport, "C10", multilang.Get(lang, multilang.KeyDoneTime))
	_ = file.SetCellValue(defs.SheetTTISupport, "D10", multilang.Get(lang, multilang.KeyProcessTime))
	_ = file.SetCellValue(defs.SheetTTISupport, "E10", multilang.Get(lang, multilang.KeyObject))
	_ = file.SetCellValue(defs.SheetTTISupport, "F10", multilang.Get(lang, multilang.KeyRequestType))
	_ = file.SetCellValue(defs.SheetTTISupport, "G10", multilang.Get(lang, multilang.KeyRequestProcess))
}

func (h *TTIHandler) renderTTISupport(file *excelize.File, suffix string, lang string, summary model.TTISupportSummaryExport, details []*model.TTISupportDetailExport) {
	// Title
	_ = file.SetCellValue(defs.SheetTTISupport, "A1", fmt.Sprintf(multilang.Get(lang, multilang.KeyTitleTTISupport), suffix))
	// Summary
	_ = file.SetCellValue(defs.SheetTTISupport, "C4", summary.TotalPending)
	_ = file.SetCellValue(defs.SheetTTISupport, "C5", summary.TotalInprogress)
	_ = file.SetCellValue(defs.SheetTTISupport, "C6", summary.TotalDone)
	_ = file.SetCellValue(defs.SheetTTISupport, "C7", summary.TotalReject)
	// Detail
	no := 1
	for _, detail := range details {
		_ = file.SetSheetRow(defs.SheetTTISupport, fmt.Sprintf("A%d", 10+no), &[]interface{}{no, detail.Created, detail.Updated, detail.Process, detail.Object, detail.Category, detail.Status})
		no += 1
	}
}

func (h *TTIHandler) renderTTIAlert(file *excelize.File, suffix string, lang string, summary model.TTIAlertSummaryExport, details []*model.TTIAlertDetailExport) {
	// Title
	_ = file.SetCellValue(defs.SheetTTIAlert, "A1", fmt.Sprintf(multilang.Get(lang, multilang.KeyTitleTTIAlert), suffix))
	// Summary
	_ = file.SetCellValue(defs.SheetTTIAlert, "C4", summary.TotalCritical)
	_ = file.SetCellValue(defs.SheetTTIAlert, "C5", summary.TotalHigh)
	_ = file.SetCellValue(defs.SheetTTIAlert, "C6", summary.TotalMedium)
	_ = file.SetCellValue(defs.SheetTTIAlert, "C7", summary.TotalLow)
	// Detail
	no := 1
	for _, detail := range details {
		_ = file.SetSheetRow(defs.SheetTTIAlert, fmt.Sprintf("A%d", 10+no), &[]interface{}{no, detail.Created, detail.Category, detail.Title, detail.Object, detail.Severity, detail.Message, detail.Link})
		no += 1
	}
}

func (h *TTIHandler) newTTIAlertPool() *ants.PoolWithFunc {
	pool, _ := ants.NewPoolWithFunc(10000, func(msg interface{}) {
		request, ok := msg.(*model.PoolAlert)
		if !ok {
			return
		}
		// Create alert
		creation, _ := clock.ParseMilliTimestamp(request.Alert.Created, clock.UTC)
		creation, _ = clock.InTimezone(creation, clock.Local)
		alert := &model.TTIAlertDetailExport{
			Timestamp: creation,
			Created:   clock.Format(creation, clock.FormatHuman),
			Category:  defs.MappingTTIAlertCategoryTitle[request.Lang][request.Alert.Cats[0]],
			Severity:  defs.MappingTTIPointTitle[request.Lang][request.Configuration.Severity.GetSeverity(request.Alert.Assess)],
			Link:      fmt.Sprintf(request.Configuration.Alert.Url, request.Alert.ID, request.Target),
		}
		var e interface{} = nil
		org := ""
		// Process event
		objects := make([]string, 0)
		for _, eventID := range request.Alert.Eids {
			event, err := h.elastic.Enduser().TTIEvent().GetByID(context.Background(), request.Target, eventID)
			if err != nil {
				return
			}
			if org == "" {
				org = event.Organization
			}
			bts, err := json.Marshal(event.Message)
			if err != nil {
				return
			}
			switch event.Category {
			case defs.CategoryPhishing, defs.CategoryImpersonate, defs.CategoryImpersonateSocial:
				var object model.TTIEventBrand
				if err = json.Unmarshal(bts, &object); err != nil {
					return
				}
				objects = append(objects, object.GetObject())
				if e == nil {
					e = &object
				}
			case defs.CategoryMalware, defs.CategoryVulnerability:
				var object model.TTIEventIntelligence
				if err = json.Unmarshal(bts, &object); err != nil {
					return
				}
				objects = append(objects, object.GetObject())
				if e == nil {
					e = &object
				}
			case defs.CategoryLeak:
				var object model.TTIEventLeak
				if err = json.Unmarshal(bts, &object); err != nil {
					return
				}
				objects = append(objects, object.GetObject())
				if e == nil {
					e = &object
				}
			case defs.CategoryCompromiseSystem:
				var object model.TTIEventCompromisedSystem
				if err = json.Unmarshal(bts, &object); err != nil {
					return
				}
				objects = append(objects, object.GetObject())
				if e == nil {
					e = &object
				}
			case defs.CategoryPortAnomaly:
				var object model.TTIEventPortAnomaly
				if err = json.Unmarshal(bts, &object); err != nil {
					return
				}
				objects = append(objects, object.GetObject())
				if e == nil {
					e = &object
				}
			case defs.CategoryTargetedVulnerability:
				var object model.TTIEventTargetedVulnerability
				if err = json.Unmarshal(bts, &object); err != nil {
					return
				}
				objects = append(objects, object.GetObject())
				if e == nil {
					e = &object
				}
			}
		}
		alert.Object = strings.Join(objects, "\n")
		// Title
		tenant, err := h.mongo.Account().GroupUser().FindByID(org)
		if err != nil {
			return
		}
		title := ""

		switch request.Lang {
		case defs.LangVI:
			title = request.Configuration.Alert.Titles[request.Alert.Cats[0]]
			alert.Message = request.Alert.Message
		case defs.LangEN:
			title = request.Configuration.Alert.TitlesEN[request.Alert.Cats[0]]
		}
		switch request.Alert.Cats[0] {
		case defs.CategoryPhishing:
			if len(request.Alert.Eids) == 1 {
				src := strings.ReplaceAll(e.(*model.TTIEventBrand).Domain, ".", "[.]")
				alert.Title = fmt.Sprintf(multilang.Get(request.Lang, multilang.KeyTitlePhishingOne), tenant.Name, src)
			} else {

				alert.Title = fmt.Sprintf(title, tenant.Name, len(request.Alert.Eids))
			}
		case defs.CategoryImpersonate:
			if len(request.Alert.Eids) == 1 {
				src := strings.ReplaceAll(e.(*model.TTIEventBrand).Domain, ".", "[.]")
				alert.Title = fmt.Sprintf(multilang.Get(request.Lang, multilang.KeyTitleImpersonateOne), tenant.Name, src)
			} else {

				alert.Title = fmt.Sprintf(title, tenant.Name, len(request.Alert.Eids))
			}
		case defs.CategoryImpersonateSocial:
			if len(request.Alert.Eids) == 1 {
				src := strings.ReplaceAll(e.(*model.TTIEventBrand).Domain, ".", "[.]")
				alert.Title = fmt.Sprintf(multilang.Get(request.Lang, multilang.KeyTitleImpersonateSocialOne), tenant.Name, src)
			} else {
				alert.Title = fmt.Sprintf(title, tenant.Name, len(request.Alert.Eids))
			}
		case defs.CategoryLeak:
			if len(request.Alert.Eids) == 1 {
				// TODO: Leak
				src := ""
				alert.Title = fmt.Sprintf(multilang.Get(request.Lang, multilang.KeyTitleImpersonateSocialOne), tenant.Name, src)
			} else {
				alert.Title = fmt.Sprintf(title, tenant.Name, len(request.Alert.Eids))
			}
		case defs.CategoryMalware, defs.CategoryVulnerability:
			alert.Title = e.(*model.TTIEventIntelligence).Title
		case defs.CategoryCompromiseSystem, defs.CategoryPortAnomaly:
			alert.Title = fmt.Sprintf(title, tenant.Name, len(request.Alert.Eids))
		case defs.CategoryTargetedVulnerability:
			event := e.(*model.TTIEventTargetedVulnerability)
			alert.Title = fmt.Sprintf(multilang.Get(request.Lang, multilang.KeyTitleTargetedVulnerabilityOne), strings.ToUpper(event.Vulnerability), event.SRC, tenant.Name)
		default:
			alert.Title = defs.TitleNA
		}
		// Success
		request.Details <- alert
	})
	// Success
	return pool
}
