package defs

type SettingAction string

// Matching mongo ti_account.group_setting doc
const (
	SettingActionReceiveAlert    SettingAction = "receive_alert"
	SettingActionReceiveFile     SettingAction = "receive_file"
	SettingActionReceiveLow      SettingAction = "receive_low"
	SettingActionReceiveMedium   SettingAction = "receive_medium"
	SettingActionReceiveHigh     SettingAction = "receive_high"
	SettingActionReceiveCritical SettingAction = "receive_critical"
	SettingActionDateReport      SettingAction = "date_report"
	SettingActionWeekReport      SettingAction = "week_report"
	SettingActionMonthReport     SettingAction = "month_report"
	SettingActionQuarterReport   SettingAction = "quarter_report"
	SettingActionDepthReport     SettingAction = "depth_report"
)

var SettingActionSeverityMap = map[SettingAction]string{
	SettingActionReceiveLow:      "Low",
	SettingActionReceiveMedium:   "Medium",
	SettingActionReceiveHigh:     "High",
	SettingActionReceiveCritical: "Critical",
}
