package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/360EntSecGroup-Skylar/excelize/v2"
	"github.com/go-resty/resty/v2"
	"github.com/labstack/echo/v4"
	es "gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic"
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/awesome-threat/library/slice"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/adapter/elastic"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/multilang"
)

type AlertHandler struct {
	elastic elastic.GlobalRepository
	mongo   mongo.GlobalRepository
	config  model.Config
}

func NewAlertHandler(conf model.Config) AlertHandlerInterface {
	handler := &AlertHandler{
		elastic: elastic.NewGlobalRepository(conf.Connector.Elastic),
		mongo:   mongo.NewGlobalRepository(conf.Connector.Mongo),
		config:  conf,
	}
	if handler.config.Api.Timeout == 0 {
		handler.config.Api.Timeout = defs.DefaultTimeout
	}
	// Success
	return handler
}

func (h *AlertHandler) Export(c echo.Context) error {
	body, err := h.verifyExport(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Body(err.Error()).Go()
	}
	// Collect
	file, _ := excelize.OpenFile(defs.DefaultAlertExport)
	// Brand Abuse
	if slice.String(body.Feature).Contains(defs.FeatureBrandAbuse) {
		// Generate
		h.renderMultilangBrandabuse(file, body.Lang)
		// Start
		results, err := h.mongo.Enduser().BrandAbuse().Alert().FindAll(body.PrepareBrandAbuseQuery(), []string{"+monitor_time"})
		if err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		mappingTargetBrandAbuse := map[string][]*model.BrandDetailExport{}
		targets := make([]string, 0)
		if !slice.String(body.Target).Contains("all") {
			targets = body.Target
		}
		for _, detail := range results {
			if slice.String(body.Target).Contains("all") {
				for _, target := range detail.Target {
					targets = append(targets, target)
					d := &model.BrandDetailExport{
						Domain:   detail.Domain,
						Created:  clock.Format(detail.MonitorTime, clock.FormatHuman),
						Target:   target,
						Category: detail.Category,
					}
					if value, ok := mappingTargetBrandAbuse[target]; ok {
						value = append(value, d)
						mappingTargetBrandAbuse[target] = value
					} else {
						mappingTargetBrandAbuse[target] = []*model.BrandDetailExport{d}
					}
				}
			} else {
				for _, target := range body.Target {
					if slice.String(detail.Target).Contains(target) {
						d := &model.BrandDetailExport{
							Domain:   detail.Domain,
							Created:  clock.Format(detail.MonitorTime, clock.FormatHuman),
							Target:   target,
							Category: detail.Category,
						}
						if value, ok := mappingTargetBrandAbuse[target]; ok {
							value = append(value, d)
							mappingTargetBrandAbuse[target] = value
						} else {
							mappingTargetBrandAbuse[target] = []*model.BrandDetailExport{d}
						}
					}
				}

			}
		}
		targets = slice.String(targets).Unique().Extract()
		// Summary
		brandabuseSummaries := make([]*model.BrandSummaryExport, 0)
		brandabuseDetails := make([]*model.BrandDetailExport, 0)
		for _, target := range targets {
			value, ok := mappingTargetBrandAbuse[target]
			if ok {
				brandabuseDetails = append(brandabuseDetails, value...)
				// Calculate
				summary := &model.BrandSummaryExport{
					Target: target,
					Detail: map[string]int{},
				}
				saved, err := h.mongo.Account().GroupUser().FindByTenantID(target)
				if err == nil {
					summary.Package = saved.Role
				}
				for _, detail := range value {
					if _, ok := summary.Detail[detail.Category]; ok {
						summary.Detail[detail.Category] += 1
					} else {
						summary.Detail[detail.Category] = 1
					}
				}
				brandabuseSummaries = append(brandabuseSummaries, summary)
			}
		}
		// Render
		h.renderBrandAbuse(file, body, brandabuseSummaries, brandabuseDetails)
		file.SetSheetName(defs.SheetBrandAbuse, multilang.Get(body.Lang, multilang.KeySheetThreatBrandAbuse))
		file.SetActiveSheet(2)
	} else {
		file.DeleteSheet(defs.SheetBrandAbuse)
	}
	if slice.String(body.Feature).Contains(defs.FeatureIntelligenceVulnerability) {
		// Generate
		h.renderMultilangVulnerability(file, body.Lang)
		// Start
		intelligenceResults, err := h.elastic.Enduser().Delivery().FindAll(context.Background(), body.PrepareIntelligenceVulnerabilityQuery(), []string{"+creation_date"})
		if err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			intelligenceResults = make([]*model.Delivery, 0)
		}
		intelligenceSummary := &model.IntelligenceSummaryExport{}
		intelligenceDetails := make([]*model.IntelligenceDetailExport, 0)
		for _, intel := range intelligenceResults {
			err = intel.Calculate()
			if len(body.Status) > 0 {
				if !slice.String(body.Status).Contains(defs.MappingSLAStatus[intel.AppearInfo.AppearStatus]) {
					continue
				}
			}
			if err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			creation, err := clock.Parse(intel.CreationDate, "")
			if err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			creation, _ = clock.ReplaceTimezone(creation, clock.Local)
			detail := &model.IntelligenceDetailExport{
				Created:  clock.Format(creation, clock.FormatHuman),
				Severity: defs.MappingPointTitle[intel.Severity],
				Status:   intel.AppearInfo.AppearStatus,
				Policy:   defs.MappingPolicy[intel.PolicyIntel],
			}
			if intel.AppearInfo.AppearTime > 0 {
				appear, err := clock.ParseTimestamp(int64(intel.AppearInfo.AppearTime), clock.Local)
				if err != nil {
					return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
				}
				appear, _ = clock.InTimezone(appear, clock.Local)
				detail.Appeared = clock.Format(appear, clock.FormatHuman)
			} else {
				detail.Appeared = defs.SLANa
			}
			intelInfo, err := h.elastic.Enduser().Intelligence().GetByID(context.Background(), intel.IntelID)
			if err != nil {
				if err.Error() != es.NotFoundError {
					return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
				}
			} else {
				detail.Title = intelInfo.InfoGeneral.Title
				detail.Summary = intelInfo.InfoGeneral.Summary
			}
			intelligenceDetails = append(intelligenceDetails, detail)
			// Calculate
			intelligenceSummary.Calculate(*detail)
		}
		// Render
		h.renderVulnerability(file, body, *intelligenceSummary, intelligenceDetails)
		file.SetSheetName(defs.SheetVulnerability, multilang.Get(body.Lang, multilang.KeySheetThreatVulnerability))
		file.SetActiveSheet(1)
	} else {
		file.DeleteSheet(defs.SheetVulnerability)
	}
	if slice.String(body.Feature).Contains(defs.FeatureIntelligenceMalware) {
		// Generate
		h.renderMultilangMalware(file, body.Lang)
		// Start
		intelligenceResults, err := h.elastic.Enduser().Delivery().FindAll(context.Background(), body.PrepareIntelligenceMalwareQuery(), []string{"+creation_date"})
		if err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			intelligenceResults = make([]*model.Delivery, 0)
		}
		intelligenceSummary := &model.IntelligenceSummaryExport{}
		intelligenceDetails := make([]*model.IntelligenceDetailExport, 0)
		for _, intel := range intelligenceResults {
			err = intel.Calculate()
			if len(body.Status) > 0 {
				if !slice.String(body.Status).Contains(defs.MappingSLAStatus[intel.AppearInfo.AppearStatus]) {
					continue
				}
			}
			if err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			creation, err := clock.Parse(intel.CreationDate, "")
			if err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			creation, _ = clock.ReplaceTimezone(creation, clock.Local)
			detail := &model.IntelligenceDetailExport{
				Created:  clock.Format(creation, clock.FormatHuman),
				Severity: defs.MappingPointTitle[intel.Severity],
				Status:   intel.AppearInfo.AppearStatus,
				Policy:   defs.MappingPolicy[intel.PolicyIntel],
			}
			if intel.AppearInfo.AppearTime > 0 {
				appear, err := clock.ParseTimestamp(int64(intel.AppearInfo.AppearTime), clock.Local)
				if err != nil {
					return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
				}
				detail.Appeared = clock.Format(appear, clock.FormatHuman)
			} else {
				detail.Appeared = defs.SLANa
			}
			intelInfo, err := h.elastic.Enduser().Intelligence().GetByID(context.Background(), intel.IntelID)
			if err != nil {
				if err.Error() != es.NotFoundError {
					return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
				}
			} else {
				detail.Title = intelInfo.InfoGeneral.Title
				detail.Summary = intelInfo.InfoGeneral.Summary
			}
			intelligenceDetails = append(intelligenceDetails, detail)
			// Calculate
			intelligenceSummary.Calculate(*detail)
		}
		// Render
		h.renderMalware(file, body, *intelligenceSummary, intelligenceDetails)
		file.SetSheetName(defs.SheetMalware, multilang.Get(body.Lang, multilang.KeySheetThreatMalware))
		file.SetActiveSheet(0)
	} else {
		file.DeleteSheet(defs.SheetMalware)
	}
	now, _ := clock.Now(clock.Local)
	nowStr := clock.Format(now, clock.FormatRFC3339C)
	nowStr = strings.ReplaceAll(nowStr, "-", "")
	nowStr = strings.ReplaceAll(nowStr, " ", "")
	nowStr = strings.ReplaceAll(nowStr, ":", "")
	filename := fmt.Sprintf(defs.DefaultAlertFileName, nowStr)
	filePath := fmt.Sprintf(defs.DefaultTempFilePath, filename)
	if err = file.SaveAs(filePath); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	defer os.Remove(filePath)
	// Send mail
	if len(body.To) > 0 {
		data := struct {
			Suffix string
		}{
			Suffix: body.GetSuffix(),
		}
		temp, err := template.New(filepath.Base(defs.DefaultReportTemplate)).ParseFiles(defs.DefaultReportTemplate)
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

func (h *AlertHandler) verifyExport(c echo.Context) (body model.RequestAlertExport, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	now, _ := clock.Now(clock.Local)
	// Feature
	if len(body.Feature) > 0 {
		for _, feature := range body.Feature {
			if !slice.String(defs.EnumFeature).Contains(feature) {
				return body, errors.New("invalid value for parameter <feature>")
			}
		}
	}
	// Severity
	if len(body.Severity) > 0 {
		for _, severity := range body.Severity {
			if !slice.String(defs.EnumSeverity).Contains(severity) {
				return body, errors.New("invalid value for parameter <severity>")
			}
		}
	}
	// Status
	if len(body.Status) > 0 {
		for _, status := range body.Status {
			if !slice.String(defs.EnumStatus).Contains(status) {
				return body, errors.New("invalid value for parameter <status>")
			}
		}
	}
	if len(body.To) > 0 {
		for _, email := range body.To {
			_, err := mail.ParseAddress(email)
			if err != nil {
				return body, errors.New("invalid value for parameter <to>")
			}
		}
	}
	// Created
	if body.Created.Gte > 0 && body.Created.Lte > 0 {
		if body.Created.Gte >= body.Created.Lte {
			return body, errors.New("created.lte > created.gte")
		}
		createdGte, _ := clock.ParseMilliTimestamp(body.Created.Gte, clock.Local)
		createdLte, _ := clock.ParseMilliTimestamp(body.Created.Lte, clock.Local)
		if createdGte.AddDate(1, 0, 0).Before(createdLte) {
			return body, errors.New("created.lte - created.gte > 1 year")
		}
	} else {
		if body.Created.Gte > 0 {
			createdGte, _ := clock.ParseMilliTimestamp(body.Created.Gte, clock.Local)
			createdLte := createdGte.AddDate(1, 0, 0)
			if createdLte.After(now) {
				body.Created.Lte = clock.UnixMilli(now)
			} else {
				body.Created.Lte = clock.UnixMilli(createdLte)
			}
		} else if body.Created.Lte > 0 {
			createdLte, _ := clock.ParseMilliTimestamp(body.Created.Lte, clock.Local)
			createdGte := createdLte.AddDate(-1, 0, 0)
			body.Created.Gte = clock.UnixMilli(createdGte)
		} else {
			return body, errors.New("created.lte, created.gte empty")
		}
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

func (h *AlertHandler) renderMultilangMalware(file *excelize.File, lang string) {
	_ = file.SetCellValue(defs.SheetMalware, "A3", multilang.Get(lang, multilang.KeySummary))
	_ = file.SetCellValue(defs.SheetMalware, "A4", multilang.Get(lang, multilang.KeySeverity))
	_ = file.SetCellValue(defs.SheetMalware, "B4", multilang.Get(lang, multilang.KeyCritical))
	_ = file.SetCellValue(defs.SheetMalware, "B5", multilang.Get(lang, multilang.KeyHigh))
	_ = file.SetCellValue(defs.SheetMalware, "B6", multilang.Get(lang, multilang.KeyMedium))
	_ = file.SetCellValue(defs.SheetMalware, "B7", multilang.Get(lang, multilang.KeyLow))
	_ = file.SetCellValue(defs.SheetMalware, "A8", multilang.Get(lang, multilang.KeyStatus))
	_ = file.SetCellValue(defs.SheetMalware, "B8", multilang.Get(lang, multilang.KeyPass))
	_ = file.SetCellValue(defs.SheetMalware, "B9", multilang.Get(lang, multilang.KeyFail))
	_ = file.SetCellValue(defs.SheetMalware, "A11", multilang.Get(lang, multilang.KeyTitleListAlerts))
	_ = file.SetCellValue(defs.SheetMalware, "A12", multilang.Get(lang, multilang.KeyNo))
	_ = file.SetCellValue(defs.SheetMalware, "B12", multilang.Get(lang, multilang.KeyTime))
	_ = file.SetCellValue(defs.SheetMalware, "C12", multilang.Get(lang, multilang.KeyAppearTime))
	_ = file.SetCellValue(defs.SheetMalware, "D12", multilang.Get(lang, multilang.KeyTitle))
	_ = file.SetCellValue(defs.SheetMalware, "E12", multilang.Get(lang, multilang.KeyDescription))
	_ = file.SetCellValue(defs.SheetMalware, "F12", multilang.Get(lang, multilang.KeyStatus))
	_ = file.SetCellValue(defs.SheetMalware, "G12", multilang.Get(lang, multilang.KeySeverity))
	_ = file.SetCellValue(defs.SheetMalware, "H12", multilang.Get(lang, multilang.KeyPermission))
}

func (h *AlertHandler) renderMultilangVulnerability(file *excelize.File, lang string) {
	_ = file.SetCellValue(defs.SheetVulnerability, "A3", multilang.Get(lang, multilang.KeySummary))
	_ = file.SetCellValue(defs.SheetVulnerability, "A4", multilang.Get(lang, multilang.KeySeverity))
	_ = file.SetCellValue(defs.SheetVulnerability, "B4", multilang.Get(lang, multilang.KeyCritical))
	_ = file.SetCellValue(defs.SheetVulnerability, "B5", multilang.Get(lang, multilang.KeyHigh))
	_ = file.SetCellValue(defs.SheetVulnerability, "B6", multilang.Get(lang, multilang.KeyMedium))
	_ = file.SetCellValue(defs.SheetVulnerability, "B7", multilang.Get(lang, multilang.KeyLow))
	_ = file.SetCellValue(defs.SheetVulnerability, "A8", multilang.Get(lang, multilang.KeyStatus))
	_ = file.SetCellValue(defs.SheetVulnerability, "B8", multilang.Get(lang, multilang.KeyPass))
	_ = file.SetCellValue(defs.SheetVulnerability, "B9", multilang.Get(lang, multilang.KeyFail))
	_ = file.SetCellValue(defs.SheetVulnerability, "A11", multilang.Get(lang, multilang.KeyTitleListAlerts))
	_ = file.SetCellValue(defs.SheetVulnerability, "A12", multilang.Get(lang, multilang.KeyNo))
	_ = file.SetCellValue(defs.SheetVulnerability, "B12", multilang.Get(lang, multilang.KeyTime))
	_ = file.SetCellValue(defs.SheetVulnerability, "C12", multilang.Get(lang, multilang.KeyAppearTime))
	_ = file.SetCellValue(defs.SheetVulnerability, "D12", multilang.Get(lang, multilang.KeyTitle))
	_ = file.SetCellValue(defs.SheetVulnerability, "E12", multilang.Get(lang, multilang.KeyDescription))
	_ = file.SetCellValue(defs.SheetVulnerability, "F12", multilang.Get(lang, multilang.KeyStatus))
	_ = file.SetCellValue(defs.SheetVulnerability, "G12", multilang.Get(lang, multilang.KeySeverity))
	_ = file.SetCellValue(defs.SheetVulnerability, "H12", multilang.Get(lang, multilang.KeyPermission))
}

func (h *AlertHandler) renderMultilangBrandabuse(file *excelize.File, lang string) {
	_ = file.SetCellValue(defs.SheetBrandAbuse, "A3", multilang.Get(lang, multilang.KeyTitleListDomains))
	_ = file.SetCellValue(defs.SheetBrandAbuse, "A4", multilang.Get(lang, multilang.KeyNo))
	_ = file.SetCellValue(defs.SheetBrandAbuse, "B4", multilang.Get(lang, multilang.KeyTime))
	_ = file.SetCellValue(defs.SheetBrandAbuse, "C4", multilang.Get(lang, multilang.KeyDomain))
	_ = file.SetCellValue(defs.SheetBrandAbuse, "D4", multilang.Get(lang, multilang.KeyType))
	_ = file.SetCellValue(defs.SheetBrandAbuse, "E4", multilang.Get(lang, multilang.KeyObject))
	_ = file.SetCellValue(defs.SheetBrandAbuse, "G3", multilang.Get(lang, multilang.KeySummary))
	_ = file.SetCellValue(defs.SheetBrandAbuse, "G4", multilang.Get(lang, multilang.KeyNo))
	_ = file.SetCellValue(defs.SheetBrandAbuse, "H4", multilang.Get(lang, multilang.KeyObject))
	_ = file.SetCellValue(defs.SheetBrandAbuse, "I4", multilang.Get(lang, multilang.KeyPackageType))
}

func (h *AlertHandler) renderMalware(file *excelize.File, request model.RequestAlertExport, summary model.IntelligenceSummaryExport, details []*model.IntelligenceDetailExport) {
	// Title
	_ = file.SetCellValue(defs.SheetMalware, "A1", fmt.Sprintf(defs.TitleSummaryMalware, request.GetSuffix()))
	// Summary
	_ = file.SetCellValue(defs.SheetMalware, "C4", summary.TotalCritical)
	_ = file.SetCellValue(defs.SheetMalware, "C5", summary.TotalHigh)
	_ = file.SetCellValue(defs.SheetMalware, "C6", summary.TotalMedium)
	_ = file.SetCellValue(defs.SheetMalware, "C7", summary.TotalLow)
	// Calculate SLA
	var deltaPass float64 = 0
	var deltaFail float64 = 0
	if summary.TotalSLAPass+summary.TotalSLAFail+summary.TotalSLANa != 0 {
		deltaPass = float64(summary.TotalSLAPass) * 100.0 / float64(summary.TotalSLAPass+summary.TotalSLAFail+summary.TotalSLANa)
		deltaFail = float64(summary.TotalSLAFail) * 100.0 / float64(summary.TotalSLAPass+summary.TotalSLAFail+summary.TotalSLANa)
	}
	_ = file.SetCellValue(defs.SheetMalware, "C8", fmt.Sprintf("%d (%.2f%%)", summary.TotalSLAPass, deltaPass))
	_ = file.SetCellValue(defs.SheetMalware, "C9", fmt.Sprintf("%d (%.2f%%)", summary.TotalSLAFail, deltaFail))
	// Detail
	no := 1
	for _, item := range details {
		_ = file.SetSheetRow(defs.SheetMalware, fmt.Sprintf("A%d", 12+no), &[]interface{}{no, item.Created, item.Appeared, item.Title, item.Summary, item.Status, item.Severity, item.Policy})
		no += 1
	}
}

func (h *AlertHandler) renderVulnerability(file *excelize.File, request model.RequestAlertExport, summary model.IntelligenceSummaryExport, details []*model.IntelligenceDetailExport) {
	// Title
	_ = file.SetCellValue(defs.SheetVulnerability, "A1", fmt.Sprintf(defs.TitleSummaryVulnerability, request.GetSuffix()))
	// Summary
	_ = file.SetCellValue(defs.SheetVulnerability, "C4", summary.TotalCritical)
	_ = file.SetCellValue(defs.SheetVulnerability, "C5", summary.TotalHigh)
	_ = file.SetCellValue(defs.SheetVulnerability, "C6", summary.TotalMedium)
	_ = file.SetCellValue(defs.SheetVulnerability, "C7", summary.TotalLow)
	// Calculate SLA
	var deltaPass float64 = 0
	var deltaFail float64 = 0
	if summary.TotalSLAPass+summary.TotalSLAFail+summary.TotalSLANa != 0 {
		deltaPass = float64(summary.TotalSLAPass) * 100.0 / float64(summary.TotalSLAPass+summary.TotalSLAFail+summary.TotalSLANa)
		deltaFail = float64(summary.TotalSLAFail) * 100.0 / float64(summary.TotalSLAPass+summary.TotalSLAFail+summary.TotalSLANa)
	}
	_ = file.SetCellValue(defs.SheetVulnerability, "C8", fmt.Sprintf("%d (%.2f%%)", summary.TotalSLAPass, deltaPass))
	_ = file.SetCellValue(defs.SheetVulnerability, "C9", fmt.Sprintf("%d (%.2f%%)", summary.TotalSLAFail, deltaFail))
	// Detail
	no := 1
	for _, item := range details {
		_ = file.SetSheetRow(defs.SheetVulnerability, fmt.Sprintf("A%d", 12+no), &[]interface{}{no, item.Created, item.Appeared, item.Title, item.Summary, item.Status, item.Severity, item.Policy})
		no += 1
	}
}

func (h *AlertHandler) renderBrandAbuse(file *excelize.File, request model.RequestAlertExport, summaries []*model.BrandSummaryExport, details []*model.BrandDetailExport) {
	// Title
	_ = file.SetCellValue(defs.SheetBrandAbuse, "A1", fmt.Sprintf(defs.TitleSummaryBrandAbuse, request.GetSuffix()))
	// Summary
	no := 1
	categories := make([]string, 0)
	for _, item := range summaries {
		for cat := range item.Detail {
			if !slice.String(categories).Contains(cat) {
				categories = append(categories, cat)
			}
		}
	}
	_ = file.SetSheetRow(defs.SheetBrandAbuse, "J4", &categories)
	for _, item := range summaries {
		data := make([]interface{}, 0)
		for _, cat := range categories {
			total := 0
			if v, ok := item.Detail[cat]; ok {
				total = v
			}
			data = append(data, total)
		}
		line := append([]interface{}{no, item.Target, item.Package}, data...)
		_ = file.SetSheetRow(defs.SheetBrandAbuse, fmt.Sprintf("G%d", 4+no), &line)
		no += 1
	}
	// Merge
	_ = file.MergeCell(defs.SheetBrandAbuse, "G3", fmt.Sprintf("%s3", string(rune(73+len(categories)))))
	// Detail
	no = 1
	for _, item := range details {
		_ = file.SetSheetRow(defs.SheetBrandAbuse, fmt.Sprintf("A%d", 4+no), &[]interface{}{no, item.Created, item.Domain, item.Category, item.Target})
		no += 1
	}
}
