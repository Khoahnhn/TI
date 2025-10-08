package handler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/labstack/echo/v4"
	mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/awesome-threat/library/slice"
	"go.mongodb.org/mongo-driver/bson"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

type RoleHandler struct {
	name   string
	logger pencil.Logger
	mongo  mongo.GlobalRepository
	config model.Config
}

func NewRoleHandler(conf model.Config) RoleHandlerInterface {
	handler := &RoleHandler{name: defs.HandlerCustomer, config: conf}
	handler.logger, _ = pencil.New(handler.name, pencil.DebugLevel, true, os.Stdout)
	handler.mongo = mongo.NewGlobalRepository(conf.Adapter.Mongo)
	// Success
	return handler
}

func (inst *RoleHandler) CreateRole(c echo.Context) error {
	body, err := inst.verifyCreate(c)
	if err != nil {
		return rest.JSON(c).Code(http.StatusBadRequest).Log(err).Go()
	}
	creator := c.Get("user_name").(string)
	now, _ := clock.Now(clock.Local)
	document := body.Generate(creator, now.UnixMilli())
	existingRole, err := inst.mongo.Account().Roles().GetByName(context.Background(), body.RoleID)
	if err != nil {
		if err.Error() != mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	if existingRole != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Message("Role existed").Log("Role code existed").Go()
	}
	if document.Mass {
		existingPaygatePackage, err := inst.mongo.Account().Roles().GetByName(context.Background(), *document.PriceListID)
		if err != nil {
			if err.Error() != mg.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
		}
		if existingPaygatePackage != nil {
			return rest.JSON(c).Code(rest.StatusBadRequest).
				Message("Paygate Package already exists in another Package").
				Log("Paygate Package already exists in another Package").
				Go()
		}
	}
	oldPerms, err := inst.processPrivileges(context.Background(), body.Privileges)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).
			Message(err.Error()).
			Log(err.Error()).
			Go()
	}
	document.Permissions = oldPerms
	document.Privileges = PrivilegesMapToArray(body.Privileges)
	// store role
	if err = inst.mongo.Account().Roles().Store(context.Background(), document); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(document.ID).Go()
}

func (inst *RoleHandler) EditRole(c echo.Context) error {
	body, err := inst.verifyEdit(c)
	if err != nil {
		return rest.JSON(c).Code(http.StatusBadRequest).Log(err).Go()
	}
	editor := c.Get("user_name").(string)
	saved, err := inst.mongo.Account().Roles().GetByName(context.Background(), body.ID)
	if err != nil {
		if err.Error() == mg.NotFoundError {
			return rest.JSON(c).
				Code(http.StatusNotFound).
				Message("package not found!").
				Log("package not found").
				Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	if body.Type == defs.PackageTypeMass {
		paygatePackage, err := inst.mongo.Account().Roles().GetByName(context.Background(), *body.PaygatePackage)
		if err != nil {
			if err.Error() != mg.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
		}
		if paygatePackage != nil && paygatePackage.RoleID != body.ID {
			return rest.JSON(c).Code(rest.StatusBadRequest).
				Message("Paygate Package already exists in another Package").
				Log("Paygate Package already exists in another Package").
				Go()
		}
	}
	oldPerms, err := inst.processPrivileges(context.Background(), body.Privileges)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).
			Message(err.Error()).
			Log(err.Error()).
			Go()
	}
	saved.Editor = editor
	saved.Mass = body.Type == defs.PackageTypeMass
	saved.Level = body.Level
	saved.Permissions = oldPerms
	saved.Description = body.Description
	saved.Month = body.Month
	saved.LimitAlert = body.LimitAlert
	saved.LimitAccount = body.LimitAccount
	saved.LimitAssetIPDomain = body.LimitIPDomain
	saved.LimitAssetProduct = body.LimitProduct
	saved.LimitAssetAliases = body.LimitAliases
	if body.Type == defs.PackageTypeMass {
		saved.ReportPackage = body.ReportPackage
		saved.PriceListID = body.PaygatePackage
		saved.PaygatePackageName = body.PaygatePackageName
	} else {
		saved.ReportPackage = nil
		saved.PriceListID = nil
		saved.PaygatePackageName = nil
	}
	switch body.Language {
	case "vi":
		saved.MultiLang[body.Language] = model.LanguageContent{Description: body.Description}
	case "en":
		saved.MultiLang[body.Language] = model.LanguageContent{Description: body.Description}
	case "jp":
		saved.MultiLang[body.Language] = model.LanguageContent{Description: body.Description}
	}
	saved.Languages = slice.String(append(saved.Languages, body.Language)).Unique().Extract()
	saved.Privileges = PrivilegesMapToArray(body.Privileges)
	now, _ := clock.Now(clock.Local)
	saved.UpdatedAt = clock.UnixMilli(now)
	// update role
	if err = inst.mongo.Account().Roles().UpdateByID(context.Background(), saved.ID, saved); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(saved.ID).Go()
}

func (inst *RoleHandler) DetailRole(c echo.Context) error {
	body, err := inst.verifyRoleID(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	document, err := inst.mongo.Account().Roles().GetByName(context.Background(), body.ID)
	if err != nil {
		if err.Error() == mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusNotFound).
				Message("package not found").
				Log("package not found").
				Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	response := model.RoleResponse{
		Role:       *document,
		Privileges: PrivilegesArrayToMap(document.Privileges),
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(response).Go()
}

func (inst *RoleHandler) DeleteRole(c echo.Context) error {
	body, err := inst.verifyRoleID(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	role, err := inst.mongo.Account().Roles().GetByName(context.Background(), body.ID)
	if err != nil {
		if err.Error() == mg.NotFoundError {
			return rest.JSON(c).
				Code(rest.StatusNotFound).
				Message("package not found").
				Log("package not found!").
				Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	organization, err := inst.mongo.Account().GroupUser().GetByRole(context.Background(), role.RoleID)
	if err != nil {
		if err.Error() != mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	if organization != nil {
		return rest.JSON(c).
			Code(rest.StatusBadRequest).
			Message("Cannot delete packages that are associated with an organization").
			Log("Cannot delete packages that are associated with an organization").
			Go()
	}
	if err = inst.mongo.Account().Roles().DeleteByID(context.Background(), role.ID); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Go()
}

func (inst *RoleHandler) Statistic(c echo.Context) error {
	body, err := inst.verifyRoleStatistic(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Message(err.Error()).Log(err).Go()
	}
	filter := bson.M{}
	if len(body.PaygatePackage) > 0 {
		filter["paygate_package_name"] = bson.M{"$in": body.PaygatePackage}
	}
	if len(body.Level) > 0 {
		filter["level"] = bson.M{"$in": body.Level}
	}
	if len(body.Features) > 0 {
		filter["privileges.resource"] = bson.M{"$in": body.Features}
	}
	if body.Keyword != "" {
		regex := regexp.QuoteMeta(body.Keyword)
		filter["$or"] = bson.A{
			bson.M{"multi_lang.vi.description": bson.M{"$regex": regex, "$options": "i"}},
			bson.M{"multi_lang.en.description": bson.M{"$regex": regex, "$options": "i"}},
			bson.M{"multi_lang.jp.description": bson.M{"$regex": regex, "$options": "i"}},
			bson.M{"role_id": bson.M{"$regex": regex, "$options": "i"}},
		}
	}
	// Aggregation cho các field khác (có filter)
	fieldsWithFilter := []string{"mass", "report_package", "level"}
	common, err := inst.mongo.Account().Roles().AggregationCount(context.Background(), &filter, fieldsWithFilter)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Aggregation riêng cho paygate_package (không filter)
	emptyFilter := bson.M{}
	paygateFields := []string{"paygate_package_name"}
	paygateResult, err := inst.mongo.Account().Roles().AggregationCount(context.Background(), &emptyFilter, paygateFields)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	result := map[string]any{}
	// types
	types := []mg.ResultAggregationCount{
		{Value: "mass", Count: 0},
		{Value: "enterprise", Count: 0},
	}
	for _, item := range common["mass"] {
		if item.Value == true {
			types[0].Count = item.Count
		} else {
			types[1].Count = item.Count
		}
	}
	result["type"] = types
	// Report package
	reportPackages := []mg.ResultAggregationCount{
		{Value: true, Count: 0},
		{Value: false, Count: 0},
	}
	for _, item := range common["report_package"] {
		for i := range reportPackages {
			if fmt.Sprintf("%v", reportPackages[i].Value) == fmt.Sprintf("%v", item.Value) {
				reportPackages[i].Count = item.Count
				break
			}
		}
	}
	result["report_package"] = reportPackages
	// level
	levels := []mg.ResultAggregationCount{
		{Value: 1, Count: 0},
		{Value: 2, Count: 0},
		{Value: 3, Count: 0},
		{Value: 4, Count: 0},
	}
	for _, item := range common["level"] {
		for i := range levels {
			if fmt.Sprintf("%v", levels[i].Value) == fmt.Sprintf("%v", item.Value) {
				levels[i].Count = item.Count
				break
			}
		}
	}
	result["level"] = levels
	// Paygate package
	result["paygate_package"] = paygateResult["paygate_package_name"]
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(result).Go()
}

func (inst *RoleHandler) Search(c echo.Context) error {
	body, err := inst.verifyRoleSearch(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	if len(body.Sort) == 0 || len(body.Sort) > 1 {
		body.Sort = []string{"-created_at"}
	}
	query := body.Query()
	results, err := inst.mongo.Account().Roles().Find(context.Background(), query, body.Sort, body.Offset, body.Size)
	if err != nil {
		if err.Error() != mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
	}
	count, err := inst.mongo.Account().Roles().Count(context.Background(), query)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": results, "total": count}).Go()
}

func (inst *RoleHandler) processPrivileges(ctx context.Context, privileges map[string]map[string]bool) ([]string, error) {
	featureCodes := make([]string, 0, len(privileges))
	for key := range privileges {
		featureCodes = append(featureCodes, key)
	}
	features, err := inst.mongo.Account().Features().GetByCode(ctx, featureCodes, 0, int64(len(featureCodes)))
	if err != nil {
		if err.Error() != mg.NotFoundError {
			return nil, err
		}
	}
	existingFeatureMap := make(map[string]bool)
	for _, feature := range features {
		existingFeatureMap[feature.Code] = true
	}
	var invalidFeatures []string
	for _, code := range featureCodes {
		if !existingFeatureMap[code] {
			invalidFeatures = append(invalidFeatures, code)
		}
	}
	if len(invalidFeatures) > 0 {
		return nil, fmt.Errorf("invalid feature IDs: %v", invalidFeatures)
	}
	permissions, err := inst.mongo.Account().Permissions().GetAll(ctx, &bson.M{}, []string{}, 0, 0)
	if err != nil {
		if err.Error() != mg.NotFoundError {
			return nil, err
		}
	}
	mapOldPerm := map[string]string{}
	for _, permission := range permissions {
		key := permission.PermissionId
		if strings.HasPrefix(key, "view_") {
			key = strings.Replace(key, "view_", "", 1)
		}
		mapOldPerm[key] = permission.PermissionId
	}
	var oldPerms []string
	for key, value := range privileges {
		if value["read"] {
			oldPerm, ok := mapOldPerm[key]
			if ok {
				oldPerms = append(oldPerms, oldPerm)
			}
		}
	}
	return oldPerms, nil
}

func PrivilegesMapToArray(m map[string]map[string]bool) []model.Privilege {
	result := make([]model.Privilege, 0, len(m))
	for resource, actionsMap := range m {
		actions := make([]string, 0, len(actionsMap))
		for action, enabled := range actionsMap {
			if enabled {
				actions = append(actions, action)
			}
		}
		if len(actions) > 0 {
			result = append(result, model.Privilege{
				Resource: resource,
				Action:   actions,
			})
		}
	}
	return result
}

func PrivilegesArrayToMap(arr []model.Privilege) map[string]map[string]bool {
	result := make(map[string]map[string]bool)
	for _, priv := range arr {
		m := make(map[string]bool)
		for _, action := range priv.Action {
			m[action] = true
		}
		result[priv.Resource] = m
	}
	return result
}

func (inst *RoleHandler) verifyCreate(c echo.Context) (bodyRequestRoleCreate model.RequestRoleCreate, err error) {
	if err = Validate(c, &bodyRequestRoleCreate); err != nil {
		log.Printf("Validate error: %v", err)
		return bodyRequestRoleCreate, err
	}
	if bodyRequestRoleCreate.Privileges == nil {
		bodyRequestRoleCreate.Privileges = make(map[string]map[string]bool)
	}
	if bodyRequestRoleCreate.Type == "mass" {
		if bodyRequestRoleCreate.ReportPackage == nil {
			return bodyRequestRoleCreate, errors.New("report_package is required for mass type")
		}
		if bodyRequestRoleCreate.PaygatePackage == nil || *bodyRequestRoleCreate.PaygatePackage == "" {
			return bodyRequestRoleCreate, errors.New("paygate is required for mass type")
		}
		if bodyRequestRoleCreate.PaygatePackageName == nil || *bodyRequestRoleCreate.PaygatePackageName == "" {
			return bodyRequestRoleCreate, errors.New("paygate is required for mass type")
		}
	}
	return bodyRequestRoleCreate, nil
}

func (inst *RoleHandler) verifyEdit(c echo.Context) (bodyRequestRoleEdit model.RequestRoleEdit, err error) {
	if err = Validate(c, &bodyRequestRoleEdit); err != nil {
		return bodyRequestRoleEdit, err
	}
	if bodyRequestRoleEdit.Type == "mass" {
		if bodyRequestRoleEdit.ReportPackage == nil {
			return bodyRequestRoleEdit, errors.New("report_package is required for mass type")
		}
		if bodyRequestRoleEdit.PaygatePackage == nil || *bodyRequestRoleEdit.PaygatePackage == "" {
			return bodyRequestRoleEdit, errors.New("paygate is required for mass type")
		}
	}
	return bodyRequestRoleEdit, nil
}

func (inst *RoleHandler) verifyRoleID(c echo.Context) (body model.RequestRoleID, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	// Success
	return body, nil
}

func (inst *RoleHandler) verifyRoleSearch(c echo.Context) (body model.RequestRoleSearch, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	// Success
	return body, nil
}

func (inst *RoleHandler) verifyRoleStatistic(c echo.Context) (body model.RequestRoleStatistic, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	// Success
	return body, nil
}
