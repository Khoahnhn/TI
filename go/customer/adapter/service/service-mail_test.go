package service

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/go-resty/resty/v2"
	mock_repo "gitlab.viettelcyber.com/ti-micro/ws-customer/mock/repo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.uber.org/mock/gomock"
)

func Test_alertService_BuildAlertConfig(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	err := errors.New("foo")

	defaultSetting := &model.DefaultConfig{
		Constant: model.ConstantConfig{
			Action: model.ConstantActionConfig{
				Alert: map[int]string{
					2: "receive_low",
				},
				Report: map[int]string{
					1: "receive_alert",
				},
			},
		},
		Feature: model.FeatureConfig{},
	}
	userSettings := []model.UserSetting{
		{
			Username: "",
			Name:     "vulnerable",
			Actions:  []model.Action{},
		},
	}
	schedules := []model.Schedule{
		{
			ExtraData: model.ExtraData{
				Key: "vulnerable",
			},
		},
	}
	groupSettings := []model.GroupSetting{
		{
			Name: "vulnerable",
			Schedule: []model.ScheduleConfig{
				{
					Type: "monthly",
					Data: model.ScheduleData{
						ByDay: &model.ByDay{},
					},
				},
			},
		},
		{
			Name: "report",
			Schedule: []model.ScheduleConfig{
				{
					Type: "daily",
				},
				{
					Type: "weekly",
				},
				{
					Type: "monthly",
					Data: model.ScheduleData{
						ByWeekDay: &model.ScheduleData{},
					},
				},
				{
					Type: "quarterly",
					Data: model.ScheduleData{
						ByNMonthIndex: &model.ScheduleData{},
					},
				},
			},
		},
	}

	type args struct {
		ctx      context.Context
		username string
		groupId  string
	}
	tests := []struct {
		name    string
		s       *alertService
		args    args
		wantNil bool
		wantErr bool
	}{
		{
			name: "default_setting_fail",
			s: func() *alertService {
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockDefaultSetting := mock_repo.NewMockDefaultSettingRepository(ctrl)

				mockAccount.EXPECT().DefaultSetting().Return(mockDefaultSetting).AnyTimes()

				mockDefaultSetting.EXPECT().GetDefaultSetting(gomock.Any()).Return(nil, err).Times(1)

				return &alertService{accountRepo: mockAccount}
			}(),
			wantNil: true,
			wantErr: true,
		},
		{
			name: "default_setting_empty",
			s: func() *alertService {
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockDefaultSetting := mock_repo.NewMockDefaultSettingRepository(ctrl)

				mockAccount.EXPECT().DefaultSetting().Return(mockDefaultSetting).AnyTimes()

				mockDefaultSetting.EXPECT().GetDefaultSetting(gomock.Any()).Return(nil, nil).Times(1)

				return &alertService{accountRepo: mockAccount}
			}(),
			wantNil: true,
			wantErr: true,
		},
		{
			name: "user_setting_fail",
			s: func() *alertService {
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockDefaultSetting := mock_repo.NewMockDefaultSettingRepository(ctrl)
				mockUserSetting := mock_repo.NewMockUserSettingRepository(ctrl)

				mockAccount.EXPECT().DefaultSetting().Return(mockDefaultSetting).AnyTimes()

				mockDefaultSetting.EXPECT().GetDefaultSetting(gomock.Any()).Return(defaultSetting, nil).Times(1)

				mockUserSetting.EXPECT().GetUserSettings(gomock.Any(), gomock.Any()).Return(nil, err).Times(1)

				return &alertService{accountRepo: mockAccount, userSettingRepo: mockUserSetting}
			}(),
			wantNil: true,
			wantErr: true,
		},
		{
			name: "schedule_fail",
			s: func() *alertService {
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockDefaultSetting := mock_repo.NewMockDefaultSettingRepository(ctrl)
				mockUserSetting := mock_repo.NewMockUserSettingRepository(ctrl)
				mockGroupSetting := mock_repo.NewMockGroupSettingRepository(ctrl)
				mockSchedule := mock_repo.NewMockScheduleRepository(ctrl)

				mockAccount.EXPECT().DefaultSetting().Return(mockDefaultSetting).AnyTimes()
				mockAccount.EXPECT().GroupSetting().Return(mockGroupSetting).AnyTimes()

				mockDefaultSetting.EXPECT().GetDefaultSetting(gomock.Any()).Return(defaultSetting, nil).Times(1)

				mockUserSetting.EXPECT().GetUserSettings(gomock.Any(), gomock.Any()).Return(userSettings, nil).Times(1)

				mockSchedule.EXPECT().GetSchedules(gomock.Any(), gomock.Any()).Return(nil, err)

				return &alertService{accountRepo: mockAccount, scheduleRepo: mockSchedule, userSettingRepo: mockUserSetting}
			}(),
			wantNil: true,
			wantErr: true,
		},
		{
			name: "group_setting_fail",
			s: func() *alertService {
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockDefaultSetting := mock_repo.NewMockDefaultSettingRepository(ctrl)
				mockUserSetting := mock_repo.NewMockUserSettingRepository(ctrl)
				mockGroupSetting := mock_repo.NewMockGroupSettingRepository(ctrl)
				mockSchedule := mock_repo.NewMockScheduleRepository(ctrl)

				mockAccount.EXPECT().DefaultSetting().Return(mockDefaultSetting).AnyTimes()
				mockAccount.EXPECT().GroupSetting().Return(mockGroupSetting).AnyTimes()

				mockDefaultSetting.EXPECT().GetDefaultSetting(gomock.Any()).Return(defaultSetting, nil).Times(1)

				mockUserSetting.EXPECT().GetUserSettings(gomock.Any(), gomock.Any()).Return(userSettings, nil).Times(1)

				mockSchedule.EXPECT().GetSchedules(gomock.Any(), gomock.Any()).Return(schedules, nil)

				mockGroupSetting.EXPECT().GetGroupSetting(gomock.Any(), gomock.Any()).Return(nil, err).Times(1)

				return &alertService{accountRepo: mockAccount, scheduleRepo: mockSchedule, userSettingRepo: mockUserSetting}
			}(),
			wantNil: true,
			wantErr: true,
		},
		{
			name: "happy_case",
			s: func() *alertService {
				mockAccount := mock_repo.NewMockAccountRepository(ctrl)
				mockDefaultSetting := mock_repo.NewMockDefaultSettingRepository(ctrl)
				mockUserSetting := mock_repo.NewMockUserSettingRepository(ctrl)
				mockGroupSetting := mock_repo.NewMockGroupSettingRepository(ctrl)
				mockSchedule := mock_repo.NewMockScheduleRepository(ctrl)

				mockAccount.EXPECT().DefaultSetting().Return(mockDefaultSetting).AnyTimes()
				mockAccount.EXPECT().GroupSetting().Return(mockGroupSetting).AnyTimes()

				mockDefaultSetting.EXPECT().GetDefaultSetting(gomock.Any()).Return(defaultSetting, nil).Times(1)

				mockUserSetting.EXPECT().GetUserSettings(gomock.Any(), gomock.Any()).Return(userSettings, nil).Times(1)

				mockSchedule.EXPECT().GetSchedules(gomock.Any(), gomock.Any()).Return(schedules, nil)

				mockGroupSetting.EXPECT().GetGroupSetting(gomock.Any(), gomock.Any()).Return(groupSettings, nil).Times(1)

				return &alertService{accountRepo: mockAccount, scheduleRepo: mockSchedule, userSettingRepo: mockUserSetting}
			}(),
			wantNil: false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.BuildAlertConfig(tt.args.ctx, tt.args.username, tt.args.groupId)
			if (err != nil) != tt.wantErr {
				t.Errorf("alertService.BuildAlertConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if (got == nil) != tt.wantNil {
				t.Errorf("alertService.BuildAlertConfig() = %v, want nil: %v", got, tt.wantNil)
			}
		})
	}
}

func Test_alertService_GetCreateAccountBanner(t *testing.T) {
	type args struct {
		lang string
	}
	tests := []struct {
		name string
		s    *alertService
		args args
	}{
		{
			name: "vi",
			s:    &alertService{},
			args: args{
				lang: "vi",
			},
		},
		{
			name: "en",
			s:    &alertService{},
			args: args{
				lang: "en",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.s.GetCreateAccountBanner(tt.args.lang)
		})
	}
}

func Test_alertService_GetDefaultEmbeds(t *testing.T) {
	type args struct {
		lang string
	}
	tests := []struct {
		name string
		s    *alertService
		args args
	}{
		{
			name: "vi",
			s:    &alertService{},
			args: args{
				lang: "vi",
			},
		},
		{
			name: "en",
			s:    &alertService{},
			args: args{
				lang: "en",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.s.GetDefaultEmbeds(tt.args.lang)
		})
	}
}

func TestNewAlertService(t *testing.T) {
	NewAlertService(
		&mock_repo.MockUserSettingRepository{},
		&mock_repo.MockScheduleRepository{},
		&mock_repo.MockAccountRepository{}, &model.MailConfig{}, "")
}

type mockTransport struct {
	Code int
	Body string
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body := io.NopCloser(strings.NewReader(m.Body))
	return &http.Response{
		StatusCode: m.Code,
		Body:       body,
		Header:     make(http.Header),
	}, nil
}

func Test_alertService_SendWelcomeEmail(t *testing.T) {
	type args struct {
		recipients   []string
		title        string
		templateName string
		data         map[string]interface{}
	}
	tests := []struct {
		name    string
		s       *alertService
		args    args
		wantErr bool
	}{
		{
			name: "happy_case",
			s: func() *alertService {
				client := resty.New()
				client.SetTransport(&mockTransport{Code: http.StatusOK})
				return &alertService{
					templatePath: "../../templates/email",
					// templatePath: "./templates/email",
					client: client,
					config: &model.MailConfig{MailAPI: "http://example.com"},
				}
			}(),
			args: args{
				recipients:   []string{"a", "b"},
				templateName: "user_public_created_vi.html",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.s.SendWelcomeEmail(tt.args.recipients, tt.args.title, tt.args.templateName, tt.args.data); (err != nil) != tt.wantErr {
				t.Errorf("alertService.SendWelcomeEmail() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
