package handler

import (
	"context"
	"fmt"
	"github.com/labstack/echo/v4"
	mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
	"net/http"
	"os"
)

type PermissionHandler struct {
	name   string
	logger pencil.Logger
	mongo  mongo.GlobalRepository
	config model.Config
}

func NewPermissionHandler(conf model.Config) PermissionHandlerInterface {
	handler := &PermissionHandler{name: defs.HandlerPermission, config: conf}
	handler.logger, _ = pencil.New(handler.name, pencil.DebugLevel, true, os.Stdout)
	handler.mongo = mongo.NewGlobalRepository(conf.Adapter.Mongo)
	// Success
	return handler
}

func (inst *PermissionHandler) GetPermissions(c echo.Context) error {
	body, err := inst.verifyGetPermissions(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	offset, limit := body.BuildPagination()
	if body.Offset == 0 && body.Size == 0 {
		offset = 0
		limit = 0
	}
	result, count, err := inst.getPermissionsWithAggregate(&body, offset, limit)
	if err != nil {
		if err.Error() != mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusNotFound).Log(err).Go()
	}

	response := map[string]interface{}{
		"data":  result,
		"count": count,
	}
	return rest.JSON(c).Code(http.StatusOK).Body(response).Go()
}

func (inst *PermissionHandler) UpdatePermission(c echo.Context) error {
	body, err := inst.verifyUpdatePermission(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	module, err := inst.mongo.Account().Features().GetByName(context.Background(), body.Module)
	if err != nil {
		if err.Error() == mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusNotFound).Log("module not found!").Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	permissionObject := model.UpdatePermission{
		Description: body.Description,
		ModuleID:    module.ID,
	}
	err = inst.mongo.Account().Permissions().UpdateByID(context.Background(), body.ID, &permissionObject)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	return rest.JSON(c).Code(rest.StatusOK).Message(module.ID).Go()
}

func (inst *PermissionHandler) ChangeModule(c echo.Context) error {
	body, err := inst.verifyChangeModule(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	moduleExist, err := inst.mongo.Account().Features().GetByName(context.Background(), body.NewModule)
	if err != nil {
		if err.Error() == mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusNotFound).Log("module not found!").Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	permissions, err := inst.mongo.Account().Permissions().GetByPermissionID(context.Background(), body.IDs, 0, int64(len(body.IDs)))
	if err != nil {
		if err.Error() != mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	existingPermission := make(map[string]bool)
	for _, permission := range permissions {
		existingPermission[permission.ID] = true
	}
	var invalidPermissions []string
	for _, permissionID := range body.IDs {
		if !existingPermission[permissionID] {
			invalidPermissions = append(invalidPermissions, permissionID)
		}
	}
	if len(invalidPermissions) > 0 {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(fmt.Sprintf("Invalid permission IDs: %v", invalidPermissions)).Go()
	}
	updateModule := model.UpdateFeature{
		IDs:       body.IDs,
		FeatureID: body.NewModule,
	}
	err = inst.mongo.Account().Permissions().UpdateFeature(context.Background(), updateModule)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	return rest.JSON(c).Code(rest.StatusOK).Message(moduleExist.ID).Go()
}

func (inst *PermissionHandler) getPermissionsWithAggregate(body *model.RequestGetPermissions, offset, limit int64) ([]*model.PermissionWithModule, int64, error) {
	matchConditions := body.BuildQuery()
	if !body.IsModule {
		matchConditions = bson.M{
			"$or": []bson.M{
				{"module_id": bson.M{"$exists": false}},
				{"module_id": nil},
				{"module_id": ""},
			},
		}
	}
	if body.Module != "" {
		childModules, err := inst.mongo.Account().Features().FindMany(context.Background(), &bson.M{"parent_id": body.Module})
		if err != nil {
			return nil, 0, err
		}
		moduleIDs := []string{body.Module}
		for _, childModule := range childModules {
			moduleIDs = append(moduleIDs, childModule.ID)
		}
		matchConditions["module_id"] = bson.M{"$in": moduleIDs}
	}
	pipeline := []*bson.M{}
	pipeline = append(pipeline, &bson.M{
		"$match": matchConditions,
	})
	dataPipeline := []*bson.M{
		{
			"$lookup": bson.M{
				"from":         defs.CollectionFeatures,
				"localField":   "module_id",
				"foreignField": "_id",
				"as":           "module",
			},
		},
		{
			"$unwind": bson.M{
				"path":                       "$module",
				"preserveNullAndEmptyArrays": true,
			},
		},
		{
			"$project": bson.M{
				"_id":           1,
				"description":   1,
				"module_id":     1,
				"permission_id": 1,
				"modified_time": 1,
				"module": bson.M{
					"_id":  1,
					"name": 1,
				},
			},
		},
	}

	if offset <= 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = 10
	}
	dataPipeline = append(dataPipeline, &bson.M{"$skip": offset})
	dataPipeline = append(dataPipeline, &bson.M{"$limit": limit})

	pipeline = append(pipeline, &bson.M{
		"$facet": bson.M{
			"data":  dataPipeline,
			"count": []*bson.M{{"$count": "total"}},
		},
	})

	type AggregateResult struct {
		Data  []*model.PermissionWithModule `bson:"data"`
		Count []struct {
			Total int64 `bson:"total"`
		} `bson:"count"`
	}

	var results []*AggregateResult
	err := inst.mongo.Account().Permissions().Aggregate(context.Background(), pipeline, &results)
	if err != nil {
		return nil, 0, err
	}

	if len(results) == 0 {
		return []*model.PermissionWithModule{}, 0, nil
	}
	data := results[0].Data

	var count int64 = 0
	if len(results[0].Count) > 0 {
		count = results[0].Count[0].Total
	}

	return data, count, nil
}

func (inst *PermissionHandler) verifyChangeModule(c echo.Context) (body model.RequestUpdateModule, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	// Success
	return body, nil
}

func (inst *PermissionHandler) verifyGetPermissions(c echo.Context) (body model.RequestGetPermissions, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	// Success
	return body, nil
}

func (inst *PermissionHandler) verifyUpdatePermission(c echo.Context) (body model.RequestUpdatePermission, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	// Success
	return body, nil
}
