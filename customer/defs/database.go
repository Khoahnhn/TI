package defs

const (
	IndexAsset        = "ti-asset"
	IndexAssetHistory = "ti-asset-history"

	DatabaseTIAccount        = "ti_account"
	CollectionGroupUser      = "group_user"
	CollectionRoles          = "roles"
	CollectionUser           = "user"
	CollectionPermissions    = "permissions"
	CollectionFeatures       = "features"
	CollectionUserHistory    = "user_history"
	CollectionUserSetting    = "user_setting"
	CollectionOrgHistory     = "organization_history"
	CollectionDefaultSetting = "default_setting"
	CollectionGroupSetting   = "group_setting"

	DatabaseSettings    = "settings"
	CollectionsSchedule = "schedule"
)

var (
	ElasticsearchQueryFilterMatchAll = map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": []interface{}{
				map[string]interface{}{
					"match_all": map[string]interface{}{},
				},
			},
		},
	}
)
