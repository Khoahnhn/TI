package model

type (
	DefaultConfig struct {
		Constant ConstantConfig `bson:"constant"`
		Feature  FeatureConfig  `bson:"feature"`
	}

	GroupSetting struct {
		SettingId int              `bson:"id"`
		GroupId   string           `bson:"group_id"`
		Name      string           `bson:"name"`
		Schedule  []ScheduleConfig `bson:"schedule"`
	}

	ConstantConfig struct {
		Action ConstantActionConfig `bson:"action"`
	}

	ConstantActionConfig struct {
		Alert  map[int]string `bson:"alert"`
		Report map[int]string `bson:"report"`
	}

	FeatureConfig struct {
		Enable []string                   `bson:"enable"`
		Config map[string]UserAlertConfig `bson:"config"`
	}

	UserAlertConfig struct {
		Id          int              `bson:"id"`
		Source      string           `bson:"source"`
		Name        string           `bson:"name"`
		Description string           `bson:"description"`
		Permission  string           `bson:"permission"`
		Actions     []ActionConfig   `bson:"actions"`
		Schedule    []ScheduleConfig `bson:"schedule"`
	}

	ActionConfig struct {
		Id     int  `bson:"id"`
		Status bool `bson:"status"`
	}

	ScheduleConfig struct {
		Type string       `bson:"type"`
		Data ScheduleData `bson:"data"`
	}
)
