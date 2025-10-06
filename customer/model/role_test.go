package model

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"reflect"
	"strings"
	"testing"
)

func PtrBool(v bool) *bool {
	return &v
}

func TestRoleGetID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want any
	}{
		{"StringID", "abc123", "abc123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &Role{ID: tt.id}
			got := r.GetID()
			if got != tt.want {
				t.Errorf("GetID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRequestRoleSearch_Query(t *testing.T) {
	tests := []struct {
		name   string
		input  RequestRoleSearch
		expect bson.M
	}{
		{
			name:   "Empty input",
			input:  RequestRoleSearch{},
			expect: bson.M{},
		},
		{
			name: "Keyword only",
			input: RequestRoleSearch{
				RequestRoleStatistic: RequestRoleStatistic{
					Keyword: "Test",
				},
			},
			expect: bson.M{
				"$or": primitive.A{
					bson.M{"multi_lang.vi.description": bson.M{"$regex": "Test", "$options": "i"}},
					bson.M{"multi_lang.en.description": bson.M{"$regex": "Test", "$options": "i"}},
					bson.M{"multi_lang.jp.description": bson.M{"$regex": "Test", "$options": "i"}},
					bson.M{"role_id": bson.M{"$regex": "Test", "$options": "i"}},
				},
			},
		},
		{
			name: "Permissions only",
			input: RequestRoleSearch{
				RequestRoleStatistic: RequestRoleStatistic{
					Features: []string{"feat1", "feat2"},
				},
			},
			expect: bson.M{"privileges.resource": bson.M{"$in": []string{"feat1", "feat2"}}},
		},
		{
			name: "PaygatePackage only",
			input: RequestRoleSearch{
				RequestRoleStatistic: RequestRoleStatistic{
					PaygatePackage: []string{"pg1", "pg2"},
				},
			},
			expect: bson.M{"paygate_package_name": bson.M{"$in": []string{"pg1", "pg2"}}},
		},
		{
			name: "Type = mass & enterprise",
			input: RequestRoleSearch{
				Type: []string{"mass", "enterprise"},
			},
			expect: bson.M{
				"mass": bson.M{"$in": []bool{true, false}},
			},
		},
		{
			name: "IsNotReport true",
			input: RequestRoleSearch{
				ReportPackage: nil,
				IsNotReport:   PtrBool(true),
			},
			expect: bson.M{
				"report_package": bson.M{
					"$ne":     true,
					"$exists": true,
				},
			},
		},
		{
			name: "Level only",
			input: RequestRoleSearch{
				RequestRoleStatistic: RequestRoleStatistic{
					Level: []int{1, 2, 3},
				},
			},
			expect: bson.M{
				"level": bson.M{"$in": []int{1, 2, 3}},
			},
		},
		{
			name: "ReportPackage with true values",
			input: RequestRoleSearch{
				ReportPackage: []string{"true"},
			},
			expect: bson.M{
				"report_package": bson.M{"$in": []bool{true}},
			},
		},
		{
			name: "ReportPackage with false values",
			input: RequestRoleSearch{
				ReportPackage: []string{"false"},
			},
			expect: bson.M{
				"report_package": bson.M{"$in": []bool{false}},
			},
		},
		{
			name: "IsNotReport with true",
			input: RequestRoleSearch{
				IsNotReport: PtrBool(true),
			},
			expect: bson.M{
				"report_package": bson.M{
					"$ne":     true,
					"$exists": true,
				},
			},
		},
		{
			name: "IsNotReport with true",
			input: RequestRoleSearch{
				IsNotReport: PtrBool(false),
			},
			expect: bson.M{
				"report_package": true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.Query()
			var gotMap bson.M
			if got != nil {
				gotMap = *got
			} else {
				gotMap = bson.M{}
			}
			if !reflect.DeepEqual(gotMap, tt.expect) {
				t.Errorf("Query(%#v) = %#v\n want %#v", tt.input, gotMap, tt.expect)
			}
			if !reflect.DeepEqual(gotMap, tt.expect) {
				t.Errorf("Mismatch in test case: %s\nGot:  %#v\nWant: %#v",
					tt.name, gotMap, tt.expect)
			}
		})
	}
}

func TestRequestRoleCreate_Generate_TableDriven(t *testing.T) {
	now := int64(1234567890)
	creator := "creator123"
	trueVal := true
	pkg123 := "pkg123"
	pkg123Name := "Package 123"

	tests := []struct {
		name                   string
		input                  *RequestRoleCreate
		wantLanguage           string
		wantMass               bool
		wantDescription        string
		wantReportPackage      *bool
		wantPaygatePackage     *string
		wantPaygatePackageName *string
	}{
		{
			name: "Mass package with en language",
			input: &RequestRoleCreate{
				RoleID:             "role1",
				Type:               "mass", // Mass package
				Month:              12,
				Level:              2,
				Language:           "en",
				LimitAccount:       5,
				LimitAlert:         5,
				LimitIPDomain:      10,
				LimitProduct:       15,
				LimitAliases:       20,
				Description:        " Description EN ",
				ReportPackage:      &trueVal,
				PaygatePackage:     &pkg123,
				PaygatePackageName: &pkg123Name,
			},
			wantLanguage:           "en",
			wantMass:               true,
			wantDescription:        "Description EN",
			wantReportPackage:      &trueVal,
			wantPaygatePackage:     &pkg123,
			wantPaygatePackageName: &pkg123Name,
		},
		{
			name: "Enterprise package with vi language",
			input: &RequestRoleCreate{
				RoleID:        "role2",
				Type:          "enterprise",
				Month:         6,
				Level:         1,
				Language:      "vi",
				LimitAccount:  2,
				LimitAlert:    2,
				LimitIPDomain: 3,
				LimitProduct:  4,
				LimitAliases:  5,
				Description:   " Mô tả Tiếng Việt ",
			},
			wantLanguage:           "vi",
			wantMass:               false,
			wantDescription:        "Mô tả Tiếng Việt",
			wantReportPackage:      nil,
			wantPaygatePackage:     nil,
			wantPaygatePackageName: nil,
		},
		{
			name: "Enterprise package with jp language",
			input: &RequestRoleCreate{
				RoleID:        "role2",
				Type:          "enterprise",
				Month:         6,
				Level:         1,
				Language:      "jp",
				LimitAccount:  2,
				LimitAlert:    2,
				LimitIPDomain: 3,
				LimitProduct:  4,
				LimitAliases:  5,
				Description:   " Mô tả Tiếng Nhật ",
			},
			wantLanguage:           "jp",
			wantMass:               false,
			wantDescription:        "Mô tả Tiếng Nhật",
			wantReportPackage:      nil,
			wantPaygatePackage:     nil,
			wantPaygatePackageName: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.Generate(creator, now)

			assert.Equal(t, hash.SHA1(tt.input.RoleID), got.ID, "ID mismatch")
			assert.Equal(t, tt.input.RoleID, got.RoleID, "RoleID mismatch")
			assert.Equal(t, tt.wantMass, got.Mass, "Mass mismatch")
			assert.Equal(t, tt.input.Month, got.Month, "Month mismatch")
			assert.Equal(t, tt.input.Level, got.Level, "Level mismatch")
			assert.Equal(t, creator, got.Creator, "Creator mismatch")

			assert.Len(t, got.Languages, 1, "Languages length mismatch")
			assert.Equal(t, tt.wantLanguage, got.Languages[0], "Language mismatch")

			assert.Equal(t, tt.input.LimitAccount, got.LimitAccount, "LimitAccount mismatch")
			assert.Equal(t, tt.input.LimitAlert, got.LimitAlert, "LimitAlert mismatch")
			assert.Equal(t, tt.input.LimitIPDomain, got.LimitAssetIPDomain, "LimitAssetIPDomain mismatch")
			assert.Equal(t, tt.input.LimitProduct, got.LimitAssetProduct, "LimitAssetProduct mismatch")
			assert.Equal(t, tt.input.LimitAliases, got.LimitAssetAliases, "LimitAssetAliases mismatch")

			assert.Equal(t, now, got.CreatedAt, "CreatedAt mismatch")

			trimmedDesc := strings.TrimSpace(tt.input.Description)
			assert.Equal(t, trimmedDesc,
				strings.TrimSpace(got.MultiLang[tt.wantLanguage].Description),
				"Description mismatch")

			if tt.wantMass {
				if tt.wantReportPackage != nil {
					require.NotNil(t, got.ReportPackage, "ReportPackage should not be nil")
					assert.Equal(t, *tt.wantReportPackage, *got.ReportPackage, "ReportPackage mismatch")
				}

				if tt.wantPaygatePackage != nil {
					require.NotNil(t, got.PriceListID, "PriceListID should not be nil")
					assert.Equal(t, *tt.wantPaygatePackage, *got.PriceListID, "PriceListID mismatch")
				}
				if tt.wantPaygatePackageName != nil {
					require.NotNil(t, got.PaygatePackageName, "PaygatePackageName should not be nil")
					assert.Equal(t, strings.TrimSpace(*tt.wantPaygatePackageName),
						strings.TrimSpace(*got.PaygatePackageName),
						"PaygatePackageName mismatch")
				}
			} else {
				assert.Nil(t, got.ReportPackage, "ReportPackage should be nil for Enterprise")
				assert.Nil(t, got.PriceListID, "PriceListID should be nil for Enterprise")
				assert.Nil(t, got.PaygatePackageName, "PaygatePackageName should be nil for Enterprise")
			}
		})
	}
}
