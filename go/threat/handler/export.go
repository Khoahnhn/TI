package handler

import (
	"encoding/json"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/labstack/echo/v4"
	"github.com/nicksnyder/go-i18n/v2/i18n"
	"github.com/xuri/excelize/v2"
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/slice"
	"golang.org/x/text/language"

	"gitlab.viettelcyber.com/ti-micro/ws-threat/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-threat/model"
)

var (
	blackColor  = "#000000"
	greenColor  = "#697F3E"
	yellowColor = "#FFC000"
	orangeColor = "#EE6900"
	redColor    = "##D60707"
	brown       = "#696969"
)

func (h *CVEHandler) ExportListExcelCVE(c echo.Context, data []model.ExportData, lang string, isTest bool, path string) error {

	//t := time.Now()
	t, _ := clock.Now(clock.Local)
	var (
		err      error
		filePath string
	)
	if isTest {
		filePath = path
	} else {
		filePath, err = filepath.Abs(".")
		if err != nil {
			return err
		}
	}

	f, sheetName, headerTexts, excelStyleIDs := initialExcelFile(c, lang, t, filePath)

	_ = f.SetCellStyle(sheetName, "A2", "U2", excelStyleIDs[1])
	_ = f.SetCellValue(sheetName, "A2", headerTexts[0])
	_ = f.SetCellValue(sheetName, "B2", headerTexts[1])
	_ = f.SetCellValue(sheetName, "C2", headerTexts[2])
	_ = f.SetCellValue(sheetName, "D2", headerTexts[3])
	_ = f.SetCellValue(sheetName, "E2", headerTexts[4])
	_ = f.SetCellValue(sheetName, "F2", headerTexts[5])
	_ = f.SetCellValue(sheetName, "G2", headerTexts[6])
	_ = f.SetCellValue(sheetName, "H2", headerTexts[7])
	_ = f.SetCellValue(sheetName, "I2", headerTexts[8])
	_ = f.SetCellValue(sheetName, "J2", headerTexts[9])
	_ = f.SetCellValue(sheetName, "K2", headerTexts[10])
	_ = f.SetCellValue(sheetName, "L2", headerTexts[11])
	_ = f.SetCellValue(sheetName, "M2", headerTexts[12])
	_ = f.SetCellValue(sheetName, "N2", headerTexts[13])
	_ = f.SetCellValue(sheetName, "O2", headerTexts[14])
	_ = f.SetCellValue(sheetName, "P2", headerTexts[15])
	_ = f.SetCellValue(sheetName, "Q2", headerTexts[16])
	_ = f.SetCellValue(sheetName, "R2", headerTexts[17])
	_ = f.SetCellValue(sheetName, "S2", headerTexts[18])
	_ = f.SetCellValue(sheetName, "T2", headerTexts[19])
	err = f.SetCellValue(sheetName, "U2", headerTexts[20])

	count := 0

	for i, alert := range data {
		if count == h.config.App.MaxSizeExport {
			break
		}
		_ = f.SetCellStyle(sheetName, fmt.Sprintf("A%d", i+3), fmt.Sprintf("F%d", i+3), excelStyleIDs[2])
		_ = f.SetCellStyle(sheetName, fmt.Sprintf("G%d", i+3), fmt.Sprintf("G%d", i+3), excelStyleIDs[7])
		_ = f.SetCellStyle(sheetName, fmt.Sprintf("J%d", i+3), fmt.Sprintf("J%d", i+3), excelStyleIDs[7])
		_ = f.SetCellStyle(sheetName, fmt.Sprintf("N%d", i+3), fmt.Sprintf("N%d", i+3), excelStyleIDs[2])
		_ = f.SetCellStyle(sheetName, fmt.Sprintf("O%d", i+3), fmt.Sprintf("O%d", i+3), excelStyleIDs[2])
		_ = f.SetCellStyle(sheetName, fmt.Sprintf("H%d", i+3), fmt.Sprintf("I%d", i+3), excelStyleIDs[2])
		_ = f.SetCellStyle(sheetName, fmt.Sprintf("K%d", i+3), fmt.Sprintf("M%d", i+3), excelStyleIDs[2])
		_ = f.SetCellStyle(sheetName, fmt.Sprintf("P%d", i+3), fmt.Sprintf("S%d", i+3), excelStyleIDs[2])
		_ = f.SetCellStyle(sheetName, fmt.Sprintf("P%d", i+3), fmt.Sprintf("T%d", i+3), excelStyleIDs[2])
		_ = f.SetCellStyle(sheetName, fmt.Sprintf("P%d", i+3), fmt.Sprintf("U%d", i+3), excelStyleIDs[2])
		_ = f.SetCellValue(sheetName, fmt.Sprintf("A%d", i+3), i+1)
		_ = f.SetCellValue(sheetName, fmt.Sprintf("B%d", i+3), alert.PublishedTime)
		_ = f.SetCellValue(sheetName, fmt.Sprintf("C%d", i+3), alert.CreateTime)
		_ = f.SetCellValue(sheetName, fmt.Sprintf("D%d", i+3), alert.AnalysisTime)
		_ = f.SetCellValue(sheetName, fmt.Sprintf("E%d", i+3), alert.ApprovedTime)
		_ = f.SetCellValue(sheetName, fmt.Sprintf("F%d", i+3), alert.CVEName)
		_ = f.SetCellValue(sheetName, fmt.Sprintf("G%d", i+3), alert.Owner)
		_ = f.SetCellValue(sheetName, fmt.Sprintf("H%d", i+3), alert.Customer)
		_ = f.SetCellValue(sheetName, fmt.Sprintf("I%d", i+3), alert.Language)
		_ = f.SetCellValue(sheetName, fmt.Sprintf("J%d", i+3), alert.Description)
		_ = f.SetCellValue(sheetName, fmt.Sprintf("K%d", i+3), alert.SeverityCVSS)

		switch alert.SeSeverityCVSSNum {
		case defs.NoneSeverity:
			_ = f.SetCellStyle(sheetName, fmt.Sprintf("K%d", i+3), fmt.Sprintf("K%d", i+3), excelStyleIDs[8])
			break
		case defs.UnkownSeverity:
			_ = f.SetCellStyle(sheetName, fmt.Sprintf("K%d", i+3), fmt.Sprintf("K%d", i+3), excelStyleIDs[8])
			break
		case defs.LowSeverity:
			_ = f.SetCellStyle(sheetName, fmt.Sprintf("K%d", i+3), fmt.Sprintf("K%d", i+3), excelStyleIDs[3])
			break
		case defs.MediumSeverity:
			_ = f.SetCellStyle(sheetName, fmt.Sprintf("K%d", i+3), fmt.Sprintf("K%d", i+3), excelStyleIDs[4])
			break
		case defs.HighSeverity:
			_ = f.SetCellStyle(sheetName, fmt.Sprintf("K%d", i+3), fmt.Sprintf("K%d", i+3), excelStyleIDs[5])
			break
		case defs.CriticalSeverity:
			_ = f.SetCellStyle(sheetName, fmt.Sprintf("K%d", i+3), fmt.Sprintf("K%d", i+3), excelStyleIDs[6])
			break

		default:
		}
		_ = f.SetCellValue(sheetName, fmt.Sprintf("M%d", i+3), alert.SeverityVCS)
		switch alert.SeSeverityVCSNum {
		case defs.UnkownSeverity:
			_ = f.SetCellStyle(sheetName, fmt.Sprintf("M%d", i+3), fmt.Sprintf("M%d", i+3), excelStyleIDs[8])
			break
		case defs.LowSeverity:
			_ = f.SetCellStyle(sheetName, fmt.Sprintf("M%d", i+3), fmt.Sprintf("M%d", i+3), excelStyleIDs[3])
			break
		case defs.MediumSeverity:
			_ = f.SetCellStyle(sheetName, fmt.Sprintf("M%d", i+3), fmt.Sprintf("M%d", i+3), excelStyleIDs[4])
			break
		case defs.HighSeverity:
			_ = f.SetCellStyle(sheetName, fmt.Sprintf("M%d", i+3), fmt.Sprintf("M%d", i+3), excelStyleIDs[5])
			break
		case defs.CriticalSeverity:
			_ = f.SetCellStyle(sheetName, fmt.Sprintf("M%d", i+3), fmt.Sprintf("M%d", i+3), excelStyleIDs[6])
			break
		default:
		}

		if alert.CVSSVersion == "" {
			_ = f.SetCellValue(sheetName, fmt.Sprintf("L%d", i+3), "N/A")
		} else {
			_ = f.SetCellValue(sheetName, fmt.Sprintf("L%d", i+3), alert.CVSSVersion)
		}

		_ = f.SetCellValue(sheetName, fmt.Sprintf("N%d", i+3), alert.UserChecklist)
		_ = f.SetCellValue(sheetName, fmt.Sprintf("O%d", i+3), alert.Status)
		_ = f.SetCellValue(sheetName, fmt.Sprintf("Q%d", i+3), "")
		if alert.ProcessDeltaTime != "" {
			_ = f.SetCellValue(sheetName, fmt.Sprintf("P%d", i+3), alert.ProcessDeltaTime)

		} else {
			_ = f.SetCellValue(sheetName, fmt.Sprintf("P%d", i+3), "N/A")
		}

		_ = f.SetCellValue(sheetName, fmt.Sprintf("S%d", i+3), "")
		if alert.ServiceDeltaTime != "" {
			_ = f.SetCellValue(sheetName, fmt.Sprintf("R%d", i+3), alert.ServiceDeltaTime)
		} else {
			_ = f.SetCellValue(sheetName, fmt.Sprintf("R%d", i+3), "N/A")
		}

		_ = f.SetCellValue(sheetName, fmt.Sprintf("T%d", i+3), alert.Source)
		_ = f.SetCellValue(sheetName, fmt.Sprintf("U%d", i+3), alert.ID)

		count++
	}

	if err := setColumnWidth(f, sheetName); err != nil {
		return err
	}
	fileName := fmt.Sprintf("VTI_cve_%s.xlsx", t.Format("150405_02012006"))

	c.Response().Header().Set("Content-Type", "application/octet-stream")
	c.Response().Header().Set("Content-Disposition", "attachment; filename="+fileName)
	c.Response().Header().Set("Content-Transfer-Encoding", "binary")
	if err := f.Write(c.Response().Writer); err != nil {
		return err
	}
	return nil
}

func setColumnWidth(f *excelize.File, sheetName string) error {
	cols, err := f.GetCols(sheetName)
	if err != nil {
		return err
	}
	for idx, col := range cols {
		largestWidth := 0
		for _, rowCell := range col[1:] {
			cellWidth := utf8.RuneCountInString(rowCell) + 6
			if cellWidth > largestWidth && cellWidth <= 200 {
				largestWidth = cellWidth
			}
		}
		name, colErr := excelize.ColumnNumberToName(idx + 1)
		if colErr != nil {
			return colErr
		}
		if name == "B" {
			_ = f.SetColWidth(sheetName, name, name, float64(23))
		} else if name == "C" {
			_ = f.SetColWidth(sheetName, name, name, float64(23))
		} else if name == "D" {
			_ = f.SetColWidth(sheetName, name, name, float64(23))
		} else if name == "E" {
			_ = f.SetColWidth(sheetName, name, name, float64(23))
		} else if name == "H" {
			_ = f.SetColWidth(sheetName, name, name, float64(13))
		} else if name == "I" {
			_ = f.SetColWidth(sheetName, name, name, float64(13))
		} else if name == "A" {
			_ = f.SetColWidth(sheetName, name, name, float64(8))
		} else if name == "P" {
			_ = f.SetColWidth(sheetName, name, name, float64(16))
		} else if name == "Q" {
			_ = f.SetColWidth(sheetName, name, name, float64(16))
		} else if name == "R" {
			_ = f.SetColWidth(sheetName, name, name, float64(16))
		} else if name == "S" {
			_ = f.SetColWidth(sheetName, name, name, float64(16))
		} else if name == "N" {
			_ = f.SetColWidth(sheetName, name, name, float64(16))
		} else if name == "K" {
			_ = f.SetColWidth(sheetName, name, name, float64(16))
		} else if name == "L" {
			_ = f.SetColWidth(sheetName, name, name, float64(16))
		} else if name == "M" {
			_ = f.SetColWidth(sheetName, name, name, float64(16))
		} else if name == "J" {
			_ = f.SetColWidth(sheetName, name, name, float64(100))
		} else if name == "T" {
			_ = f.SetColWidth(sheetName, name, name, float64(16))
		} else if name == "U" {
			_ = f.SetColWidth(sheetName, name, name, float64(50))
		} else {
			_ = f.SetColWidth(sheetName, name, name, float64(largestWidth))
		}

	}

	return nil
}
func initialExcelFile(c echo.Context, lang string, t time.Time, filePath string) (*excelize.File, string, []string, []int) {
	var i18nBundle *i18n.Bundle
	if lang == defs.LangVI {
		i18nBundle = i18n.NewBundle(language.Vietnamese)
	} else {
		i18nBundle = i18n.NewBundle(language.English)
	}

	i18nBundle.RegisterUnmarshalFunc("json", json.Unmarshal)

	i18nBundle.MustLoadMessageFile(fmt.Sprintf("%s/%s", filePath, `locales/messages.en.json`))
	i18nBundle.MustLoadMessageFile(fmt.Sprintf("%s/%s", filePath, `locales/messages.vi.json`))
	localizer := i18n.NewLocalizer(i18nBundle, lang)

	header0Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-list"})
	header1Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-01"})
	header2Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-02"})
	header3Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-03"})
	header4Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-04"})
	header5Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-05"})
	header6Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-06"})
	header7Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-07"})
	header8Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-08"})
	header9Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-09"})
	header10Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-10"})
	header11Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-11"})
	header12Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-12"})
	header13Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-13"})
	header14Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-14"})
	header15Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-15"})
	header16Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-16"})
	header17Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-17"})
	header18Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-18"})
	header19Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-19"})
	header20Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-20"})
	header21Text := localizer.MustLocalize(&i18n.LocalizeConfig{MessageID: "export-header-21"})

	headerText := []string{header1Text, header2Text, header3Text, header4Text, header5Text, header6Text, header7Text, header8Text, header9Text,
		header10Text, header11Text, header12Text, header13Text, header14Text, header15Text, header16Text, header17Text, header18Text, header19Text, header20Text, header21Text}

	file := excelize.NewFile()
	var sheetName string

	sheetName = t.Format("150405_02012006")
	index, _ := file.NewSheet(sheetName)
	_ = file.DeleteSheet("Sheet1")

	_, excelBorderStyle, _, excelHeader0Style, excelHeaderStyle, excelContentStyle, excelContentUrlStyle,
		_, excelSeverityLowStyle, excelSeverityMediumStyle, excelSeverityHighStyle, excelSeverityCriticalStyle, excelSeverityNAStyle := initialExcelStyle()

	file.SetDefaultFont("Times New Roman")
	severityLowStyle, _ := file.NewStyle(excelSeverityLowStyle)
	severityMediumStyle, _ := file.NewStyle(excelSeverityMediumStyle)
	severityHighStyle, _ := file.NewStyle(excelSeverityHighStyle)
	severityCriticalStyle, _ := file.NewStyle(excelSeverityCriticalStyle)
	severityNaStyle, _ := file.NewStyle(excelSeverityNAStyle)

	borderStyle, _ := file.NewStyle(excelBorderStyle)
	headerStyle, _ := file.NewStyle(excelHeaderStyle)
	header0Style, _ := file.NewStyle(excelHeader0Style)
	contentStyle, _ := file.NewStyle(excelContentStyle)
	contentUrlStyle, _ := file.NewStyle(excelContentUrlStyle)

	excelStyleIDs := []int{borderStyle, headerStyle, contentStyle, severityLowStyle, severityMediumStyle, severityHighStyle, severityCriticalStyle, contentUrlStyle, severityNaStyle}

	_ = file.SetCellStyle(sheetName, "A2", "U2", header0Style)
	_ = file.SetCellValue(sheetName, "A2", header0Text)

	_ = file.SetRowHeight(sheetName, 21, float64(25))

	file.SetActiveSheet(index)

	return file, sheetName, headerText, excelStyleIDs
}

func initialExcelStyle() (excelTitleStyle, excelBorderStyle, excelOverviewStyle, excelHeader0Style, excelHeaderStyle, excelContentStyle,
	excelContentUrlStyle, excelSeverityStyle, excelSeverityLowStyle, excelSeverityMediumStyle, excelSeverityHighStyle, excelSeverityCriticalStyle, excelSeverityNAStyle *excelize.Style) {
	centerAlign := &excelize.Alignment{
		Horizontal: "center",
		Vertical:   "center",
		WrapText:   true,
	}

	excelBorder := []excelize.Border{
		{
			Type:  "top",
			Color: blackColor,
			Style: 1,
		},
		{
			Type:  "right",
			Color: blackColor,
			Style: 1,
		},
		{
			Type:  "bottom",
			Color: blackColor,
			Style: 1,
		},
		{
			Type:  "left",
			Color: blackColor,
			Style: 1,
		},
	}

	fill := excelize.Fill{
		Type:    "pattern",
		Pattern: 1,
		Color:   []string{"#9BC2E6"},
	}

	excelTitleStyle = &excelize.Style{
		Font: &excelize.Font{
			Bold: true,
			Size: 14,
		},
	}

	excelBorderStyle = &excelize.Style{
		Border: excelBorder,
	}

	excelOverviewStyle = &excelize.Style{
		Font: &excelize.Font{
			Bold: true,
			Size: 11,
		},
		Fill:   fill,
		Border: excelBorder,
	}

	excelHeader0Style = &excelize.Style{
		Font: &excelize.Font{
			Bold: true,
			Size: 11,
		},
		Border: excelBorder,
	}

	excelHeaderStyle = &excelize.Style{
		Font: &excelize.Font{
			Bold: true,
			Size: 11,
		},
		Fill:      fill,
		Alignment: centerAlign,
		Border:    excelBorder,
	}

	excelContentStyle = &excelize.Style{
		Font: &excelize.Font{
			Size: 11,
		},
		Alignment: &excelize.Alignment{
			Horizontal: "center",
			Vertical:   "center",
		},
		Border: excelBorder,
	}

	excelContentUrlStyle = &excelize.Style{
		Font: &excelize.Font{
			Size: 11,
		},
		Alignment: &excelize.Alignment{
			Horizontal: "left",
			Vertical:   "center",
			WrapText:   true,
		},
		Border: excelBorder,
	}

	excelSeverityStyle = &excelize.Style{
		Font: &excelize.Font{
			Size: 11,
		},
		Alignment: centerAlign,
		Border:    excelBorder,
	}

	excelSeverityLowStyle = &excelize.Style{
		Font: &excelize.Font{
			Size:  11,
			Bold:  true,
			Color: greenColor,
		},
		Alignment: centerAlign,
		Border:    excelBorder,
	}

	excelSeverityMediumStyle = &excelize.Style{
		Font: &excelize.Font{
			Size:  11,
			Bold:  true,
			Color: yellowColor,
		},
		Alignment: centerAlign,
		Border:    excelBorder,
	}

	excelSeverityHighStyle = &excelize.Style{
		Font: &excelize.Font{
			Size:  11,
			Bold:  true,
			Color: orangeColor,
		},
		Alignment: centerAlign,
		Border:    excelBorder,
	}

	excelSeverityCriticalStyle = &excelize.Style{
		Font: &excelize.Font{
			Size:  11,
			Bold:  true,
			Color: redColor,
		},
		Alignment: centerAlign,
		Border:    excelBorder,
	}

	excelSeverityNAStyle = &excelize.Style{
		Font: &excelize.Font{
			Size:  11,
			Bold:  true,
			Color: brown,
		},
		Alignment: centerAlign,
		Border:    excelBorder,
	}
	return
}

func countSeverity(data []model.ExportData) (int64, int64, int64, int64, int64) {
	var (
		severityLow      int64
		severityMedium   int64
		severityHigh     int64
		severityCritical int64
		severityNA       int64
	)

	for _, alert := range data {
		switch alert.SeSeverityVCSNum {
		case defs.LowSeverity:
			severityLow += 1
		case defs.MediumSeverity:
			severityMedium += 1
		case defs.HighSeverity:
			severityHigh += 1
		case defs.CriticalSeverity:
			severityCritical += 1
		case defs.UnkownSeverity:
			severityNA += 1
		default:
		}
	}

	return severityLow, severityMedium, severityHigh, severityCritical, severityNA
}

func getExportExcelData(listCve []*model.CVE, req model.RequestCVESearch, lang string) []model.ExportData {
	result := make([]model.ExportData, 0)
	listSeverity := map[int]string{}
	if lang == "vi" {
		listSeverity = map[int]string{
			0: "N/A",
			1: "Thấp",
			2: "Trung bình",
			3: "Cao",
			4: "Nghiêm trọng",
		}
	} else {
		listSeverity = map[int]string{
			0: "N/A",
			1: "Low",
			2: "Medium",
			3: "High",
			4: "Critical",
		}
	}
	listSeverityCVSS := map[int]string{}
	if lang == "vi" {
		listSeverityCVSS = map[int]string{
			-1: "Không xác định",
			0:  "Không ảnh hưởng",
			1:  "Thấp",
			2:  "Trung bình",
			3:  "Cao",
			4:  "Nghiêm trọng",
		}
	} else {
		listSeverityCVSS = map[int]string{
			-1: "Unknown",
			0:  "None",
			1:  "Low",
			2:  "Medium",
			3:  "High",
			4:  "Critical",
		}
	}

	//sort.Slice(listCve, func(i, j int) bool {
	//	return listCve[i].Modified < listCve[j].Modified
	//})
	loc, _ := clock.LoadLocation(clock.Local)
	for _, v := range listCve {
		item := model.ExportData{}
		item.ID = v.ID
		modifiedTime := time.Unix(v.Published/1000, 0).In(loc)
		item.PublishedTime = modifiedTime.Format("15:04:05 02/01/2006")
		creatTime := time.Unix(v.Created/1000, 0).In(loc)
		item.CreateTime = creatTime.Format("15:04:05 02/01/2006")

		if v.AnalysisTime == 0 {
			item.AnalysisTime = "N/A"
		} else {
			analysisTime := time.Unix(v.AnalysisTime/1000, 0).In(loc)
			item.AnalysisTime = analysisTime.Format("15:04:05 02/01/2006")
		}

		item.ProcessSLA = "N/A"
		item.ServiceSLA = "N/A"
		if v.Status != defs.StatusCodeApproved {
			v.Approved = 0
		}

		lan := make([]string, 0)
		for _, v := range v.Languages {
			if v == defs.LangVI {
				lan = append(lan, "VI")
			}

			if v == defs.LangEN {
				lan = append(lan, "EN")
			}
		}
		item.Language = strings.Join(lan, ",")

		item.CVEName = v.Name

		if slice.String(v.Languages).Contains(defs.LangVI) && len(v.Languages) == 1 {
			if v.Searchable.VI.Description == "" {
				item.Description = "N/A"
			} else {
				item.Description = v.Searchable.VI.Description
			}
		}
		if slice.String(v.Languages).Contains(defs.LangEN) && len(v.Languages) == 1 {
			if v.Searchable.EN.Description == "" {
				item.Description = "N/A"
			} else {
				item.Description = v.Searchable.EN.Description
			}
		}

		if len(v.Languages) > 1 {
			if v.Searchable.VI.Description == "" {
				item.Description = "N/A"
			} else {
				item.Description = v.Searchable.VI.Description
			}
		}

		//if lang == "vi" {
		//	if v.Searchable.EN.Description == "" {
		//		item.Description = "English language support is unavailable"
		//	} else {
		//		item.Description = v.Searchable.EN.Description
		//	}
		//} else {
		//	if v.Searchable.EN.Description == "" {
		//		item.Description = "English language support is unavailable"
		//	} else {
		//		item.Description = v.Searchable.EN.Description
		//	}
		//}

		vd := make([]string, 0)
		for _, v := range v.Vendor {
			vendor := strings.ReplaceAll(v, "-", "_")
			vendorPath := strings.Split(vendor, "_")
			vendorVerbose := make([]string, 0)
			for _, v := range vendorPath {
				vendorVerbose = append(vendorVerbose, strings.Title(strings.ToLower(v)))
			}
			vendor = strings.Join(vendorVerbose, " ")
			vd = append(vd, vendor)
		}
		item.Owner = strings.Join(vd, ", ")
		item.Customer = len(v.Customer)
		item.UserChecklist = v.Checker
		switch v.Status {
		case 0:
			item.Status = "Unknown"
		case 1:
			item.Status = "New"
		case 2:
			item.Status = "Approved"
		case 3:
			item.Status = "WaitApprove"
		case 4:
			item.Status = "Delivery"
		case 5:
			item.Status = "Reject"

		}

		item.SeverityCVSS = listSeverityCVSS[v.Score.Global.Severity]
		item.CVSSVersion = v.Score.Global.Version
		item.SeverityVCS = listSeverity[v.Score.VTI.Severity]
		item.SeSeverityVCSNum = defs.Severity(v.Score.VTI.Severity)
		item.SeSeverityCVSSNum = defs.Severity(v.Score.Global.Severity)
		item.Source = v.Source
		if v.Approved != 0 {
			approveTime := time.Unix(v.Approved/1000, 0).In(loc)
			item.ApprovedTime = approveTime.Format("15:04:05 02/01/2006")
		} else {
			item.ApprovedTime = "N/A"
		}
		if v.Approved != 0 && v.AnalysisTime != 0 {
			item.ProcessDeltaTime = fmt.Sprintf("%v", math.Round(((float64(v.Approved-v.AnalysisTime)/3600)/1000)*100)/100)
		} else {
			item.ProcessDeltaTime = "N/A"
		}

		if v.Approved != 0 && v.Published != 0 {
			item.ServiceDeltaTime = fmt.Sprintf("%v", math.Round(((float64(v.Approved-v.Published)/3600)/1000)*100)/100)

		} else {
			item.ServiceDeltaTime = "N/A"
		}
		//if v.ApproveTime == 00 {
		//	item.ProcessDeltaTime = "N/A"
		//	item.ServiceDeltaTime = "N/A"
		//	item.ApprovedTime = "N/A"
		//} else {
		//
		//	if (item.SeverityCVSS == listSeverityCVSS[3] || item.SeverityCVSS == listSeverityCVSS[4]) && item.Customer > 0 {
		//		item.ServiceDeltaTime = fmt.Sprintf("%v", math.Round(((float64(v.ApproveTime-v.Published)/3600)/1000)*100)/100)
		//		item.ProcessDeltaTime = fmt.Sprintf("%v", math.Round(((float64(v.ApproveTime-v.AnalysisTime)/3600)/1000)*100)/100)
		//	}
		//	approveTime := time.Unix(v.ApproveTime/1000, 0).In(loc)
		//	item.ApprovedTime = approveTime.Format("15:04:05 02/01/2006")
		//}
		result = append(result, item)
	}
	return result
}
