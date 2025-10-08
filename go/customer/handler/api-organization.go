package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	mongolib "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/utils"
	"go.mongodb.org/mongo-driver/bson"
)

type OrganizationHandler struct {
	name   string
	logger pencil.Logger
	mongo  mongo.GlobalRepository
	config model.Config
}

func NewOrganizationHandler(conf model.Config) OrganizationHandlerInterface {
	handler := &OrganizationHandler{name: defs.HandlerOrganization, config: conf}
	handler.logger, _ = pencil.New(handler.name, pencil.DebugLevel, true, os.Stdout)
	handler.mongo = mongo.NewGlobalRepository(conf.Adapter.Mongo)

	return handler
}

func (h *OrganizationHandler) SearchOrganizations(c echo.Context) error {
	req := model.RequestSearchOrganization{}
	if err := Validate(c, &req); err != nil {
		h.logger.Errorf("failed to bind request: %v", err)
		return rest.JSON(c).Code(http.StatusBadRequest).Go()
	}
	req.SearchTerm = strings.TrimSpace(req.SearchTerm)

	orgs, err := h.getPagingOrganizations(c.Request().Context(), &req)
	if err != nil {
		h.logger.Errorf("failed to query organizations: %v, query: %+v", err, req)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}
	responseOrgs := make([]model.ResponseOrganization, len(orgs))
	for i, org := range orgs {
		responseOrgs[i].Organization = org.Organization
		responseOrgs[i].MassAlertLimit = org.Package.LimitAlert
		responseOrgs[i].PackageMass = org.Package.Mass
		if multilang, ok := org.Package.MultiLang[string(defs.LanguageVietnamese)]; ok {
			responseOrgs[i].PackageName = multilang.Description
		} else {
			responseOrgs[i].PackageName = org.Package.Description
		}
	}
	response := model.ResponseSearchOrganization{
		Total: len(responseOrgs),
		Data:  responseOrgs,
	}

	return rest.JSON(c).Code(http.StatusOK).Body(response).Go()
}

func (h *OrganizationHandler) ListOrganizations(c echo.Context) error {
	query := bson.M{
		"active": true,
	}
	data, err := h.mongo.Account().GroupUser().FindAllOrgs(c.Request().Context(), &query, []string{})
	if err != nil {
		h.logger.Errorf("failed to query organizations: %v", err)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}
	return rest.JSON(c).Code(http.StatusOK).Body(map[string]any{"data": data}).Go()
}

func (h *OrganizationHandler) Statistics(c echo.Context) error {
	req := model.RequestSearchOrganization{}
	if err := Validate(c, &req); err != nil {
		h.logger.Errorf("failed to bind request: %v", err)
		return rest.JSON(c).Code(http.StatusBadRequest).Go()
	}
	req.SearchTerm = strings.TrimSpace(req.SearchTerm)

	response := []*model.OrganizationStats{}

	query := h.buildFirstLevelSearchQuery(&req, true)
	pipeline := h.buildStatisticPipeline(query)
	err := h.mongo.Account().GroupUser().RunAggPipeline(c.Request().Context(), pipeline, &response)
	if err != nil {
		h.logger.Errorf("failed to query organizations stats: %v", err)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}
	if len(response) == 0 {
		return rest.JSON(c).Code(http.StatusOK).Body(map[string]any{"data": model.ResponseOrganizationStatistic{
			Status:      []model.AggBoolFieldValuev3{},
			PackageType: []model.AggBoolFieldValuev3{},
		}}).Go()
	}
	data := response[0]
	activeBuckets := make([]model.AggBoolFieldValuev3, 2)
	packageTypeBuckets := make([]model.AggBoolFieldValuev3, 2)

	activeBuckets[0] = model.AggBoolFieldValuev3{
		Value: true, // active
		Count: int64(data.ActiveCount),
	}
	activeBuckets[1] = model.AggBoolFieldValuev3{
		Value: false,
		Count: int64(data.Total - data.ActiveCount),
	}

	packageTypeBuckets[0] = model.AggBoolFieldValuev3{
		Value: true,
		Count: int64(data.MassCount),
	}
	packageTypeBuckets[1] = model.AggBoolFieldValuev3{
		Value: false,
		Count: int64(data.Total - data.MassCount),
	}

	industries := []model.IndustrySector{}
	for _, industry := range data.Industries {
		desc, ok := defs.IndustryKeyMap[industry]
		if !ok {
			continue
		}
		industries = append(industries, model.IndustrySector{
			Value: industry,
			Desc:  desc,
		})
	}

	stats := model.ResponseOrganizationStatistic{
		Status:       activeBuckets,
		PackageType:  packageTypeBuckets,
		PackageNames: data.Packages,
		Industries:   industries,
	}

	return rest.JSON(c).Code(http.StatusOK).Body(map[string]any{"data": stats}).Go()
}

func (h *OrganizationHandler) ListIndustry(c echo.Context) error {
	industries := []model.IndustrySector{}
	for val, desc := range defs.IndustryKeyMap {
		industries = append(industries, model.IndustrySector{
			Value: val,
			Desc:  desc,
		})
	}
	return rest.JSON(c).Code(http.StatusOK).Body(map[string]any{"data": industries}).Go()
}

func (h *OrganizationHandler) DetailOrganization(c echo.Context) error {
	id := c.Param("id")
	org, err := h.mongo.Account().GroupUser().GetOrg(c.Request().Context(), id, nil)
	if err != nil {
		h.logger.Errorf("failed to get org %v: %v", id, err)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}
	if org == nil {
		h.logger.Errorf("org %v not found", id)
		return rest.JSON(c).Code(http.StatusNotFound).Go()
	}

	return rest.JSON(c).Code(http.StatusOK).Body(org).Go()
}

func (h *OrganizationHandler) CreateOrganizations(c echo.Context) error {
	org := model.RequestStoreOrganization{}
	if err := Validate(c, &org); err != nil {
		h.logger.Errorf("failed to bind request: %v", err)
		return rest.JSON(c).Code(http.StatusBadRequest).Go()
	}
	username, ok := c.Get("user_name").(string)
	if !ok || len(username) == 0 {
		h.logger.Error("username not found")
		return rest.JSON(c).Code(http.StatusBadRequest).Go()
	}

	code, err := h.validateStoreOrgRequest(c.Request().Context(), &org)
	if err != nil {
		msg := ""
		if code != http.StatusInternalServerError {
			msg = err.Error()
		}
		return rest.JSON(c).Code(code).Message(msg).Go()
	}

	existed, err := h.mongo.Account().GroupUser().Get(c.Request().Context(), org.TenantId)
	if err != nil && err.Error() != mongolib.NotFoundError {
		h.logger.Errorf("failed to get org %v: %v", org.TenantId, err)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}
	if existed != nil {
		h.logger.Errorf("tenant id already existed: %v", org.TenantId)
		return rest.JSON(c).Code(http.StatusBadRequest).Message("tenant_id existed").Go()
	}

	insert := &model.Organization{}
	buildOrganizationFromStoreRequest(&org, insert)
	now := time.Now().UnixMilli()
	insert.CreatedTime = now
	insert.UpdatedTime = now
	insert.GenID()
	err = h.mongo.Account().GroupUser().InsertOrg(c.Request().Context(), insert)
	if err != nil {
		h.logger.Errorf("failed to insert group user: %v", err)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}
	history := model.OrganizationHistory{
		Creator:     username,
		OrgId:       insert.Id,
		Event:       defs.OrgEventCreate,
		CreatedTime: now,
	}

	err = h.mongo.Account().OrgHistory().Insert(c.Request().Context(), &history)
	if err != nil {
		h.logger.Errorf("failed to insert org history: %v", err)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}

	return c.JSON(http.StatusOK, map[string]string{"_id": insert.Id})
}

func (h *OrganizationHandler) UpdateOrganization(c echo.Context) error {
	org := model.RequestStoreOrganization{}
	if err := Validate(c, &org); err != nil {
		h.logger.Errorf("failed to bind request: %v", err)
		return rest.JSON(c).Code(http.StatusBadRequest).Go()
	}
	username, ok := c.Get("user_name").(string)
	id := c.Param("id")
	if !ok || len(username) == 0 {
		h.logger.Error("username not found")
		return rest.JSON(c).Code(http.StatusBadRequest).Go()
	}

	code, err := h.validateStoreOrgRequest(c.Request().Context(), &org)
	if err != nil {
		msg := ""
		if code != http.StatusInternalServerError {
			msg = err.Error()
		}
		return rest.JSON(c).Code(code).Message(msg).Go()
	}

	original, err := h.mongo.Account().GroupUser().GetOrg(c.Request().Context(), id, nil)
	if err != nil && err.Error() != mongolib.NotFoundError {
		h.logger.Errorf("failed to get org %v: %v", id, err)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}
	if original == nil {
		h.logger.Errorf("org not found: %v", id)
		return rest.JSON(c).Code(http.StatusBadRequest).Message("org not found").Go()
	}
	if utils.SliceContains(defs.ImmutableOrgs, original.TenantId) {
		h.logger.Error("tried to edit root")
		return rest.JSON(c).Code(http.StatusBadRequest).Message("tried to edit root").Go()
	}
	if org.TenantId != original.TenantId {
		h.logger.Errorf("tenant_id mismatch got %v, expected %v", org.TenantId, original.TenantId)
		return rest.JSON(c).Code(http.StatusBadRequest).Message("tenant_id mistmatched").Go()
	}
	if utils.SliceContains(org.Parent.Ancestors, original.TenantId) {
		h.logger.Errorf("tried to set a node to its predecessor's child", org.TenantId, original.TenantId)
		return rest.JSON(c).Code(http.StatusBadRequest).Message("invalid parent").Go()
	}

	now := time.Now().UnixMilli()
	updated := *original
	buildOrganizationFromStoreRequest(&org, &updated)

	originalJson, err := json.Marshal(original)
	if err != nil {
		h.logger.Errorf("failed to marshal org %+v: %v", original, err)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}
	updatedJson, err := json.Marshal(updated)
	if err != nil {
		h.logger.Errorf("failed to marshal org %+v: %v", updated, err)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}
	diff, err := utils.GetChangedFieldsJson(originalJson, updatedJson, defs.OrganizationCompKeys)
	if err != nil {
		h.logger.Errorf("failed to get changed fields between %+v and %+v: %v", original, updated, err)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}
	if len(diff) == 0 {
		h.logger.Errorf("nothing to update")
		return rest.JSON(c).Code(http.StatusOK).Go()
	}

	updated.Id = original.Id
	updated.CreatedTime = original.CreatedTime
	updated.UpdatedTime = now
	err = h.mongo.Account().GroupUser().UpdateOrg(c.Request().Context(), &updated)
	if err != nil {
		h.logger.Errorf("failed to update org %v: %v", id, err)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}
	// Update all descendant's ancestor array to match change
	err = h.mongo.Account().GroupUser().UpdateMany(c.Request().Context(),
		&bson.M{"$expr": bson.M{
			"$eq": bson.A{
				bson.M{"$slice": bson.A{"$ancestors", 0, len(original.Ancestors)}},
				original.Ancestors,
			},
		}},
		bson.A{bson.M{"$set": bson.M{
			"ancestors": bson.M{
				"$concatArrays": bson.A{
					updated.Ancestors,
					bson.M{
						"$slice": bson.A{"$ancestors", len(original.Ancestors), 100},
					}},
			},
		}}},
		false,
	)
	if err != nil {
		h.logger.Errorf("failed to update children's org path: %v", err)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}

	actions := make([]string, 0)
	beforeChange := make(map[string]any)
	afterChange := make(map[string]any)
	for k, r := range diff {
		actions = append(actions, k)
		beforeChange[k] = r.Before
		afterChange[k] = r.After
	}
	jsonBefore, _ := json.Marshal(beforeChange)
	jsonAfer, _ := json.Marshal(afterChange)

	history := model.OrganizationHistory{
		Creator:     username,
		OrgId:       original.Id,
		Event:       defs.OrgEventEdit,
		CreatedTime: now,
		OrgBefore:   string(jsonBefore),
		OrgAfter:    string(jsonAfer),
		Actions:     actions,
	}

	err = h.mongo.Account().OrgHistory().Insert(c.Request().Context(), &history)
	if err != nil {
		h.logger.Errorf("failed to insert org history: %v", err)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}

	return rest.JSON(c).Code(http.StatusOK).Go()
}

func (h *OrganizationHandler) ChangeStatus(c echo.Context) error {
	req := model.RequestOrganizationChangeStatus{}
	if err := Validate(c, &req); err != nil {
		h.logger.Errorf("failed to bind request: %v", err)
		return rest.JSON(c).Code(http.StatusBadRequest).Go()
	}
	username, ok := c.Get("user_name").(string)
	if !ok || len(username) == 0 {
		h.logger.Error("username not found")
		return rest.JSON(c).Code(http.StatusBadRequest).Go()
	}

	orgs, err := h.mongo.Account().GroupUser().FindAllOrgs(c.Request().Context(), &bson.M{
		"_id": bson.M{"$in": req.Ids},
	}, []string{})
	if err != nil {
		h.logger.Errorf("failed to get batch orgs: %v", err)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}
	if len(orgs) == 0 {
		h.logger.Errorf("no matched orgs for request ids: %v", req.Ids)
		return rest.JSON(c).Code(http.StatusBadRequest).Message("no matched org").Go()
	}

	package_mp := map[string]*model.Role{}
	histories := []*model.OrganizationHistory{}
	event := defs.OrgEventActive
	if !req.Active {
		event = defs.OrgEventInActive
	}
	now := time.Now()
	updated := []*model.Organization{}
	for _, org := range orgs {
		if utils.SliceContains(defs.ImmutableOrgs, org.TenantId) {
			h.logger.Error("tried to edit root")
			return rest.JSON(c).Code(http.StatusBadRequest).Message("tried to edit root").Body(map[string]any{
				"code": defs.OrgErrEditRoot,
			}).Go()
		}
		if org.Active == req.Active {
			continue
		}
		org.Active = req.Active
		org.UpdatedTime = now.UnixMilli()
		updated = append(updated, org)
		package_mp[org.Role] = nil
		histories = append(histories, &model.OrganizationHistory{
			OrgId:       org.Id,
			Creator:     username,
			Event:       event,
			CreatedTime: now.UnixMilli(),
		})
	}

	if req.Active && req.UpdateTime {
		package_ids := utils.MapKeysToSlice(package_mp)
		roles, err := h.mongo.Account().Roles().FindAll(c.Request().Context(), &bson.M{"role_id": bson.M{"$in": package_ids}}, []string{})
		if err != nil {
			h.logger.Errorf("failed to get batch roles: %v", err)
			return rest.JSON(c).Code(http.StatusInternalServerError).Go()
		}
		for _, role := range roles {
			package_mp[role.RoleID] = role
		}
		for _, org := range updated {
			pkg := package_mp[org.Role]
			if pkg != nil {
				expired := addMonthsAndRound(now, pkg.Month)
				org.EffectiveTime = getDayStartTime(now).Unix()
				org.ExpiredTime = expired.Unix()
			}
		}
	}

	if len(updated) > 0 {
		err = h.mongo.Account().GroupUserV2().BulkUpdateById(c.Request().Context(), updated)
		if err != nil {
			h.logger.Errorf("failed bulk update orgs: %v", err)
			return rest.JSON(c).Code(http.StatusInternalServerError).Go()
		}

		err = h.mongo.Account().OrgHistory().InsertMany(c.Request().Context(), histories)
		if err != nil {
			h.logger.Errorf("failed inserting org history: %v", err)
			return rest.JSON(c).Code(http.StatusInternalServerError).Go()
		}
	}

	return rest.JSON(c).Code(http.StatusOK).Go()
}

func (h *OrganizationHandler) GetHistories(c echo.Context) error {
	req := model.RequestOrganizationHistories{}
	if err := Validate(c, &req); err != nil {
		h.logger.Errorf("failed to bind request: %v", err)
		return rest.JSON(c).Code(http.StatusBadRequest).Go()
	}
	orgId := c.Param("org_id")
	filter := bson.M{"org_id": orgId}
	timeFilter := bson.M{"$gte": req.Time.StartTime}

	if len(req.Event) > 0 {
		filter["event"] = req.Event
	}
	if req.Time.EndTime > 0 {
		timeFilter["$lte"] = req.Time.EndTime
	}
	filter["created_time"] = timeFilter

	histories, err := h.mongo.Account().OrgHistory().Find(c.Request().Context(), &filter, []string{"-created_time"})
	if err != nil {
		h.logger.Errorf("failed to get org history: %v", err)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}
	return rest.JSON(c).Code(http.StatusOK).Body(map[string]any{"data": histories}).Go()
}

func (h *OrganizationHandler) GetHistoryDetail(c echo.Context) error {
	id := c.Param("id")

	detail, err := h.mongo.Account().OrgHistory().Get(c.Request().Context(), id)
	if err != nil {
		h.logger.Errorf("failed to get history detail for id %v: %v", id, err)
		return rest.JSON(c).Code(http.StatusInternalServerError).Go()
	}
	if detail == nil {
		h.logger.Errorf("no history detail with id %v", id)
		return rest.JSON(c).Code(http.StatusNotFound).Go()
	}

	return rest.JSON(c).Code(http.StatusOK).Body(map[string]any{"data": detail}).Go()
}

func (h *OrganizationHandler) getPagingOrganizations(ctx context.Context, request *model.RequestSearchOrganization) ([]*model.OrganizationSearchData, error) {
	query := h.buildFirstLevelSearchQuery(request, false)
	pipeline := h.buildSearchAggPipeline(query)

	res := []*model.OrganizationSearchData{}
	if err := h.mongo.Account().GroupUser().RunAggPipeline(ctx, pipeline, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func (h *OrganizationHandler) buildFirstLevelSearchQuery(request *model.RequestSearchOrganization, ignoreSelectBox bool) *bson.M {
	query := bson.M{}
	effectiveTimeQuery := bson.M{}
	expiredTimeQuery := bson.M{}
	if request.EffectiveInterval.StartTime > 0 {
		effectiveTimeQuery["$gte"] = request.EffectiveInterval.StartTime
	}
	if request.EffectiveInterval.EndTime > 0 {
		effectiveTimeQuery["$lte"] = request.EffectiveInterval.EndTime
	}
	if request.ExpiredInterval.StartTime > 0 {
		expiredTimeQuery["$gte"] = request.ExpiredInterval.StartTime
	}
	if request.ExpiredInterval.EndTime > 0 {
		expiredTimeQuery["$lte"] = request.ExpiredInterval.EndTime
	}
	if len(effectiveTimeQuery) > 0 {
		query["effective_time"] = effectiveTimeQuery
	}
	if len(expiredTimeQuery) > 0 {
		query["expired_time"] = expiredTimeQuery
	}

	if len(request.Package) > 0 {
		query["package.multi_lang.vi.description"] = bson.M{
			"$in": request.Package,
		}
	}
	if len(request.SearchTerm) > 0 {
		escaped := regexp.QuoteMeta(request.SearchTerm)
		query["$or"] = bson.A{
			bson.M{"name": bson.M{"$regex": escaped, "$options": "i"}},
			bson.M{"tenant_id": bson.M{"$regex": escaped, "$options": "i"}},
		}
	}
	if len(request.IndustrySector) > 0 {
		query["industry"] = bson.M{
			"$in": request.IndustrySector,
		}
	}
	if len(request.StatusActive) == 1 && !ignoreSelectBox {
		query["active"] = request.StatusActive[0]
	}
	if len(request.TypeIsMass) == 1 && !ignoreSelectBox {
		// Look up roles, rename to package
		query["package.mass"] = request.TypeIsMass[0]
	}

	return &query
}

func (h *OrganizationHandler) buildSearchAggPipeline(query *bson.M) []*bson.M {
	pipeline := []*bson.M{}
	pipeline = append(pipeline, &bson.M{
		"$lookup": bson.M{
			"from":         defs.CollectionRoles,
			"localField":   "role",
			"foreignField": "role_id",
			"as":           "package",
		},
	})

	pipeline = append(pipeline, &bson.M{
		"$match": query,
	})

	pipeline = append(pipeline, &bson.M{
		"$group": bson.M{
			"_id": nil,
			"allPaths": bson.M{
				"$push": "$ancestors",
			},
		},
	})

	pipeline = append(pipeline, &bson.M{
		"$project": bson.M{
			"allIds": bson.M{
				"$reduce": bson.M{
					"input":        "$allPaths",
					"initialValue": bson.A{},
					"in":           bson.M{"$setUnion": bson.A{"$$value", "$$this"}},
				},
			},
		},
	})

	pipeline = append(pipeline, &bson.M{
		"$lookup": bson.M{
			"from":         defs.CollectionGroupUser,
			"localField":   "allIds",
			"foreignField": "tenant_id",
			"as":           "touchedNodes",
		},
	})

	pipeline = append(pipeline, &bson.M{
		"$unwind": "$touchedNodes",
	}, &bson.M{
		"$replaceRoot": bson.M{
			"newRoot": "$touchedNodes",
		},
	})

	pipeline = append(pipeline, &bson.M{
		"$lookup": bson.M{
			"from":         defs.CollectionRoles,
			"localField":   "role",
			"foreignField": "role_id",
			"as":           "package",
		},
	})

	pipeline = append(pipeline, &bson.M{
		"$unwind": bson.M{
			"path":                       "$package",
			"preserveNullAndEmptyArrays": true,
		},
	})

	pipeline = append(pipeline, &bson.M{
		"$sort": bson.M{
			"created_time": -1,
		},
	})

	return pipeline
}

func (h *OrganizationHandler) buildStatisticPipeline(query *bson.M) []*bson.M {
	pipeline := []*bson.M{}

	pipeline = append(pipeline, &bson.M{
		"$lookup": bson.M{
			"from":         defs.CollectionRoles,
			"localField":   "role",
			"foreignField": "role_id",
			"as":           "package",
		},
	})

	pipeline = append(pipeline, &bson.M{
		"$match": query,
	})

	pipeline = append(pipeline, &bson.M{
		"$unwind": bson.M{
			"path":                       "$package",
			"preserveNullAndEmptyArrays": true,
		},
	})

	totalPipeline := []bson.M{}
	activeCntPipeline := []bson.M{
		{
			"$match": bson.M{"active": true},
		},
	}
	massCntPipeline := []bson.M{
		{
			"$match": bson.M{"package.mass": true},
		},
	}

	industriesPipeline := []bson.M{
		{
			"$group": bson.M{
				"_id":   nil,
				"names": bson.M{"$push": "$industry"},
			},
		},
		{
			"$project": bson.M{
				"_id": 0,
				"names": bson.M{
					"$reduce": bson.M{
						"input":        "$names",
						"initialValue": bson.A{},
						"in": bson.M{
							"$setUnion": bson.A{
								"$$value",
								bson.M{"$ifNull": bson.A{"$$this", bson.A{}}},
							},
						},
					},
				},
			},
		},
	}

	packagesPipeline := []bson.M{
		{
			"$group": bson.M{
				"_id": nil,
				"names": bson.M{
					"$addToSet": "$package.multi_lang.vi.description",
				},
			},
		},
	}

	pipeline = append(pipeline, &bson.M{
		"$facet": bson.M{
			"total":        totalPipeline,
			"active_count": activeCntPipeline,
			"mass_count":   massCntPipeline,
			"industries":   industriesPipeline,
			"packages":     packagesPipeline,
		},
	})

	pipeline = append(pipeline, &bson.M{
		"$project": bson.M{
			"total":        bson.M{"$size": "$total"},
			"active_count": bson.M{"$size": "$active_count"},
			"mass_count":   bson.M{"$size": "$mass_count"},
			"industries":   "$industries.names",
			"packages":     "$packages.names",
		},
	}, &bson.M{
		"$unwind": "$industries",
	}, &bson.M{
		"$unwind": "$packages",
	})

	return pipeline
}

func (h *OrganizationHandler) validateStoreOrgRequest(ctx context.Context, request *model.RequestStoreOrganization) (code int, err error) {
	// Validate org store request
	for _, industry := range request.Industry {
		if _, ok := defs.IndustryKeyMap[industry]; !ok {
			h.logger.Errorf("unknown industry: %v", industry)
			return http.StatusBadRequest, errors.New("invalid industry")
		}
	}

	if !utils.SliceContains(defs.LangList, request.Lang) {
		h.logger.Errorf("invalid lang: %v", request.Lang)
		return http.StatusBadRequest, errors.New("invalid lang")
	}

	if len(request.Name) == 0 {
		h.logger.Errorf("empty name")
		return http.StatusBadRequest, errors.New("invalid name")
	}

	if request.EffectiveTime > request.ExpiredTime {
		h.logger.Errorf("effective time(%v) > expired time(%v)", request.EffectiveTime, request.ExpiredTime)
		return http.StatusBadRequest, errors.New("invalid expired time")
	}

	role, err := h.mongo.Account().Roles().GetByName(ctx, request.PackageId)
	if err != nil {
		h.logger.Errorf("failed to get role %v: %v", request.PackageId, err)
		return http.StatusInternalServerError, err
	}
	if role.ReportPackage != nil && *role.ReportPackage {
		h.logger.Errorf("tried to use report package %v", request.PackageId)
		return http.StatusBadRequest, errors.New("invalid package")
	}
	request.Role = role
	// Set effective_time, expired_time if empty
	if request.EffectiveTime == 0 || request.ExpiredTime == 0 {
		request.EffectiveTime = getDayStartTime(time.Now()).Unix()
		request.ExpiredTime = addMonthsAndRound(time.Now(), role.Month).Unix()
	}

	parent, err := h.mongo.Account().GroupUser().GetOrg(ctx, request.ParentId, nil)
	if err != nil {
		h.logger.Errorf("failed to get parent with id %v: %v", request.ParentId, err)
		return http.StatusInternalServerError, err
	}
	request.Parent = parent
	return 0, nil
}

func buildOrganizationFromStoreRequest(request *model.RequestStoreOrganization, result *model.Organization) {
	originalRole := result.Role
	result.TenantId = request.TenantId
	result.Description = request.Description
	result.Active = request.Active
	result.Parent = request.Parent.TenantId
	result.ParentName = request.Parent.Multilang.Vi.Name
	result.ParentId = request.Parent.Id
	result.Ancestors = append(request.Parent.Ancestors, request.TenantId)
	result.Industry = request.Industry
	result.Role = request.Role.RoleID
	result.EffectiveTime = request.EffectiveTime
	result.ExpiredTime = request.ExpiredTime
	result.CompanySize = request.CompanySize
	orgInfo := &model.OrganizationInfo{Name: request.Name}
	if len(result.Lang) == 0 {
		result.Multilang.Vi = orgInfo
	}

	if !utils.SliceContains(result.Lang, request.Lang) {
		result.Lang = append(result.Lang, request.Lang)
	}

	if result.Name == "" || len(request.Lang) == 0 {
		result.Name = request.Name
	}

	switch request.Lang {
	case defs.LanguageVietnamese:
		result.Multilang.Vi = orgInfo
		result.Name = request.Name
	case defs.LanguageEnglish:
		result.Multilang.En = orgInfo
	case defs.LanguageJapanese:
		result.Multilang.Jp = orgInfo
	}

	limitAlert := request.Role.LimitAlert
	if request.Role.Mass {
		if limitAlert == 0 {
			result.ExpiredTime = 0
		}
		if request.Role.RoleID != originalRole {
			result.MassAlertQuota = limitAlert
			result.MassNextSyncTime = int(addMonthsAndRound(time.Now(), request.Role.Month).UnixMilli())
		}
	}
}

func addMonthsAndRound(original time.Time, months int) time.Time {
	addedMonth := original.AddDate(0, months, 0)
	rounded := getDayStartTime(addedMonth)
	return rounded
}

func getDayStartTime(now time.Time) time.Time {
	dayStart := time.Date(
		now.Year(), now.Month(), now.Day(),
		0, 0, 0, 0,
		now.Location(),
	)
	return dayStart
}
