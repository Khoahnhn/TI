package handler

import (
	"context"
	"errors"
	"github.com/labstack/echo/v4"
	mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/awesome-threat/library/slice"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
	"net/http"
	"os"
	"time"
)

type FeatureHandler struct {
	name   string
	logger pencil.Logger
	mongo  mongo.GlobalRepository
	config model.Config
}

func NewFeatureHandler(conf model.Config) FeatureHandlerInterface {
	handler := &FeatureHandler{name: defs.HandlerFeature, config: conf}
	handler.logger, _ = pencil.New(handler.name, pencil.DebugLevel, true, os.Stdout)
	handler.mongo = mongo.NewGlobalRepository(conf.Adapter.Mongo)
	// Success
	return handler
}

func (inst *FeatureHandler) Create(c echo.Context) error {
	body, err := inst.verifyCreateFeature(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	creator := c.Get("user_name").(string)
	now, _ := clock.Now(clock.Local)
	existingFeature, err := inst.mongo.Account().Features().GetByName(context.Background(), body.Code)
	if err != nil {
		if err.Error() != mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	if existingFeature != nil {
		return rest.JSON(c).
			Code(rest.StatusBadRequest).
			Message("Feature existed").
			Log("Feature code existed").
			Go()
	}
	var ancestors []string
	if body.ParentFeature != "" {
		parentFeature, err := inst.validateParentFeature(body.ParentFeature, body.Code, "")
		if err != nil {
			if err.Error() == "parent feature not found" {
				return rest.JSON(c).Code(rest.StatusBadRequest).Message(err.Error()).Go()
			}
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		ancestors = slice.String(append(ancestors, parentFeature.Ancestors...)).Unique().Extract()
	}
	doc := model.Feature{
		Name:        body.Name,
		Code:        body.Code,
		Description: body.Description,
		ParentID:    body.ParentFeature,
		Actions:     body.Permissions,
		Ancestors:   slice.String(append(ancestors, body.Code)).Unique().Extract(),
		Weight:      body.Weight,
		Creator:     creator,
		CreatedAt:   now.UnixMilli(),
		UpdatedAt:   now.UnixMilli(),
	}
	doc.GenID()
	err = inst.mongo.Account().Features().Store(context.Background(), &doc)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	return rest.JSON(c).Code(rest.StatusOK).Body(doc.ID).Go()
}

func (inst *FeatureHandler) Edit(c echo.Context) error {
	body, err := inst.verifyEditFeature(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	editor := c.Get("user_name").(string)
	now, _ := clock.Now(clock.Local)
	saved, err := inst.mongo.Account().Features().GetByName(context.Background(), body.ID)
	if err != nil {
		if err.Error() == mg.NotFoundError {
			return rest.JSON(c).Code(http.StatusNotFound).
				Message("Feature not found!").Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	oldAncestors := saved.Ancestors
	if body.ParentFeature != "" {
		parentFeature, err := inst.validateParentFeature(body.ParentFeature, body.ID, saved.ParentID)
		if err != nil {
			if err.Error() == "parent feature not found" ||
				err.Error() == "feature cannot be parent of itself" ||
				err.Error() == "cannot create circular parent-child relationship" {
				return rest.JSON(c).Code(rest.StatusBadRequest).Message("Parent feature not found or invalid").Go()
			}
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		saved.Ancestors = slice.String(append(parentFeature.Ancestors, body.ID)).Unique().Extract()
	} else {
		saved.Ancestors = []string{body.ID}
	}
	if len(body.Permissions) > 0 {
		saved.Actions = slice.String(append(saved.Actions, body.Permissions...)).Unique().Extract()
	}
	saved.Editor = editor
	saved.UpdatedAt = now.UnixMilli()
	saved.Weight = body.Weight
	saved.Name = body.Name
	saved.Description = body.Description
	saved.Actions = body.Permissions
	saved.ParentID = body.ParentFeature
	if err = inst.mongo.Account().Features().UpdateByID(context.Background(), saved.ID, saved); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	if !areAncestorsEqual(oldAncestors, saved.Ancestors) {
		if err := inst.bulkUpdateDescendantsAncestors(context.Background(), saved, editor); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	return rest.JSON(c).Code(rest.StatusOK).Body(saved.ID).Go()
}

func (inst *FeatureHandler) DetailFeature(c echo.Context) error {
	body, err := inst.verifyCode(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	document, err := inst.mongo.Account().Features().GetByName(context.Background(), body.ID)
	if err != nil {
		if err.Error() == mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusNotFound).
				Message("Feature not found").
				Log("Feature not found").
				Go()
		}
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(document).Go()
}

func (inst *FeatureHandler) GetAllFeature(c echo.Context) error {
	body, err := inst.verifyFeatureList(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	if len(body.Sort) == 0 {
		body.Sort = []string{"-created_at"}
	}
	query := body.Query()
	if body.FeatureCode != "" {
		feature, err := inst.mongo.Account().Features().GetByName(context.Background(), body.FeatureCode)
		if err != nil {
			if err.Error() == mg.NotFoundError {
				return rest.JSON(c).Code(rest.StatusNotFound).
					Message("Feature not found").
					Log("Feature not found").
					Go()
			}
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		hideFilter := bson.M{
			"code":      bson.M{"$ne": feature.Code},
			"ancestors": bson.M{"$nin": bson.A{feature.Code}},
		}
		combined := bson.M{"$and": bson.A{*query, hideFilter}}
		query = &combined
	}
	results, err := inst.mongo.Account().Features().Find(context.Background(), query, body.Sort, body.Offset, body.Size)
	if err != nil {
		if err.Error() != mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
	}
	count, err := inst.mongo.Account().Features().Count(context.Background(), query)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": results, "total": count}).Go()
}

func (inst *FeatureHandler) validateParentFeature(
	parentFeatureCode string,
	currentFeatureCode string,
	currentParentID string,
) (*model.Feature, error) {
	if parentFeatureCode == "" {
		return nil, nil
	}
	if parentFeatureCode == currentFeatureCode {
		return nil, errors.New("feature cannot be parent of itself")
	}
	parentFeature, err := inst.mongo.Account().Features().GetByName(context.Background(), parentFeatureCode)
	if err != nil {
		if err.Error() == mg.NotFoundError {
			return nil, errors.New("parent feature not found")
		}
		return nil, err
	}
	if currentParentID != "" && parentFeature.Code == currentParentID {
		return parentFeature, nil
	}
	ancestorsToCheck := append(parentFeature.Ancestors, parentFeature.Code)
	for _, ancestorCode := range ancestorsToCheck {
		if ancestorCode == currentFeatureCode {
			return nil, errors.New("cannot create circular parent-child relationship")
		}
	}
	return parentFeature, nil
}

func BuildFeatureTree(modules []*model.FeatureWithPermissions) []*model.FeatureWithPermissions {
	moduleMap := make(map[string]*model.FeatureWithPermissions)
	for i := range modules {
		moduleMap[modules[i].ID] = modules[i]
	}
	var roots []*model.FeatureWithPermissions
	for i := range modules {
		m := modules[i]
		if m.ParentID != "" {
			if parent, ok := moduleMap[m.ParentID]; ok {
				parent.Children = append(parent.Children, m)
			}
		} else {
			roots = append(roots, m)
		}
	}
	return roots
}

func (inst *FeatureHandler) bulkUpdateDescendantsAncestors(ctx context.Context, changedNode *model.Feature, editor string) error {
	descendants, err := inst.mongo.Account().Features().FindDescendantsByCode(ctx, changedNode.Code, 0, 0)
	if err != nil {
		return err
	}
	codeToNode := map[string]*model.Feature{changedNode.Code: changedNode}
	for _, node := range descendants {
		codeToNode[node.Code] = node
	}
	for _, node := range descendants {
		newAncestorsPrefix := changedNode.Ancestors
		idx := -1
		for i, code := range node.Ancestors {
			if code == changedNode.Code {
				idx = i
				break
			}
		}
		if idx == -1 {
			continue
		}
		tailAncestors := node.Ancestors[idx+1:]
		node.Ancestors = append(append([]string{}, newAncestorsPrefix...), changedNode.Code)
		node.Ancestors = append(node.Ancestors, tailAncestors...)
		node.Editor = editor
		node.UpdatedAt = time.Now().UnixMilli()
		// Update vào DB
		if err := inst.mongo.Account().Features().UpdateByID(ctx, node.ID, node); err != nil {
			return err
		}
	}
	return nil
}

func areAncestorsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (inst *FeatureHandler) verifyCode(c echo.Context) (body model.RequestCode, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	return body, nil
}

func (inst *FeatureHandler) verifyCreateFeature(c echo.Context) (body model.RequestCreateFeature, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	return body, nil
}

func (inst *FeatureHandler) verifyEditFeature(c echo.Context) (body model.RequestEditFeature, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	return body, nil
}

func (inst *FeatureHandler) verifyFeatureList(c echo.Context) (body model.RequestFeatureList, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	// Success
	return body, nil
}
