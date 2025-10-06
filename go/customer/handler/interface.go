package handler

import (
	"context"

	"github.com/labstack/echo/v4"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
)

type (
	AssetHandlerInterface interface {
		Config(c echo.Context) error
		Action(c echo.Context) error
		History(c echo.Context) error
	}

	AssetDomainIPAddressInterface interface {
		Search(c echo.Context) error
		Statistic(c echo.Context) error
		GetTags(c echo.Context) error
		Create(c echo.Context) error
		Owner(c echo.Context) error
		Edit(c echo.Context) error
		Validate(c echo.Context) error
		Delete(c echo.Context) error
		Upload(c echo.Context) error
		Import(c echo.Context) error
		Exist(c echo.Context) error
		Synchronize(c echo.Context) error
	}

	AssetProductHandlerInterface interface {
		Search(c echo.Context) error
		Statistic(c echo.Context) error
		Create(c echo.Context) error
		Edit(c echo.Context) error
		Delete(c echo.Context) error
		Upload(c echo.Context) error
		Import(c echo.Context) error
		Exist(c echo.Context) error
		Synchronize(c echo.Context) error
		DownloadReport(c echo.Context) error
	}

	RoleHandlerInterface interface {
		CreateRole(c echo.Context) error
		EditRole(c echo.Context) error
		DetailRole(c echo.Context) error
		DeleteRole(c echo.Context) error
		Search(c echo.Context) error
		Statistic(c echo.Context) error
	}

	OrganizationHandlerInterface interface {
		SearchOrganizations(c echo.Context) error
		ListOrganizations(c echo.Context) error
		Statistics(c echo.Context) error
		CreateOrganizations(c echo.Context) error
		ListIndustry(c echo.Context) error
		DetailOrganization(c echo.Context) error
		UpdateOrganization(c echo.Context) error
		GetHistories(c echo.Context) error
		GetHistoryDetail(c echo.Context) error
		ChangeStatus(c echo.Context) error
	}

	ManagerUserHandlerInterface interface {
		List(c echo.Context) error
		StatisticV3(c echo.Context) error
		ChangeStatus(c echo.Context) error
		Detail(c echo.Context) error
		CreatePublicUser(c echo.Context) error
		DeletePublicUser(c echo.Context) error
		UpdatePublicUser(c echo.Context) error
		ListUserHistory(c echo.Context) error
		GetUserHistoryDetail(c echo.Context) error
		GetUserHistories(
			c context.Context,
			search *model.SearchUserHistory,
			sorts []bson.M,
			offset, limit int64,
		) ([]*model.UserHistory, int64, error)
		GetPositionJobs(c echo.Context) error
		GetCountries(c echo.Context) error
		GetAlertConfig(c echo.Context) error
		SetupMail(user *model.UserV3, password, apiKey string, group *model.Organization, role *model.Role) error
		GetOrganization(c echo.Context) error
		SearchOrganization(c echo.Context) error
		CreateUser(c echo.Context) error
		GetUsers(c echo.Context) error
		GetStatistical(c echo.Context) error
		GetUser(c echo.Context) error
		EditUser(c echo.Context) error
		DeleteUser(c echo.Context) error
	}

	PermissionHandlerInterface interface {
		GetPermissions(c echo.Context) error
		UpdatePermission(c echo.Context) error
		ChangeModule(c echo.Context) error
	}
	FeatureHandlerInterface interface {
		Create(c echo.Context) error
		Edit(c echo.Context) error
		DetailFeature(c echo.Context) error
		GetAllFeature(c echo.Context) error
	}
)
