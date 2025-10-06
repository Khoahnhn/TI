package handler

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"

	"github.com/labstack/echo/v4"
	"github.com/panjf2000/ants"
	es "gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic/exception"
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/awesome-threat/library/slice"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/adapter/elastic"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

type AssetHandler struct {
	name    string
	logger  pencil.Logger
	elastic elastic.GlobalRepository
	config  model.Config
	kafka   *KafkaHandler
}

func NewAssetHandler(conf model.Config, kafka *KafkaHandler) AssetHandlerInterface {
	handler := &AssetHandler{name: defs.HandlerAsset, config: conf}
	handler.logger, _ = pencil.New(handler.name, pencil.DebugLevel, true, os.Stdout)
	handler.elastic = elastic.NewGlobalRepository(conf.Adapter.Elastic)
	handler.kafka = kafka
	// Success
	return handler
}

func (inst *AssetHandler) Config(c echo.Context) error {
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{
		"active":       defs.MappingAssetActive,
		"status":       defs.MappingAssetStatus,
		"type":         defs.MappingAssetType,
		"product_part": defs.MappingProductPart,
	}).Go()
}

func (inst *AssetHandler) Action(c echo.Context) error {
	creator := c.Get("user_name").(string)
	body, err := inst.verifyAction(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	wg := &sync.WaitGroup{}
	p, _ := ants.NewPoolWithFunc(defs.DefaultPoolSize, func(msg interface{}) {
		defer wg.Done()
		id := msg.(string)
		var oldAsset model.Asset
		saved, err := inst.elastic.Enduser().Asset().GetByID(context.Background(), id)
		if err != nil {
			inst.logger.Errorf("failed to get asset (%s), reason: %v", id, err)
			return
		}
		oldAsset = *saved
		update := false
		now, _ := clock.Now(clock.Local)
		nowTimestamp := clock.UnixMilli(now)
		kafkaAction := defs.TitleActionEdit
		switch body.Action {
		case defs.ActionActive:
			if !saved.Active {
				saved.Active = true
				update = true
			}
		case defs.ActionDeactive:
			if saved.Active {
				saved.Active = false
				update = true
			}
		case defs.ActionApprove:
			if saved.Status != defs.AssetStatusCodeApproved {
				saved.Status = defs.AssetStatusCodeApproved
				saved.Active = true
				saved.ApprovedAt = nowTimestamp
				saved.SLA = nowTimestamp - saved.Created
				update = true

				kafkaAction = defs.TitleActionApprove
			}
		case defs.ActionReject:
			if saved.Status != defs.AssetStatusCodeReject {
				saved.Status = defs.AssetStatusCodeReject
				saved.Active = false
				saved.ApprovedAt = nowTimestamp
				saved.Reason = body.Reason
				saved.SLA = nowTimestamp - saved.Created
				update = true
			}
		case defs.ActionDelete:
			if saved.Visible {
				saved.Visible = false
				saved.Active = false
				saved.Tags = nil
				update = true
			}
		}
		if update {
			saved.Modified = nowTimestamp
			if err = inst.elastic.Enduser().Asset().Update(context.Background(), saved); err != nil {
				inst.logger.Errorf("failed to update asset (%s), reason: %v", id, err)
				return
			}
			history := &model.AssetHistory{
				Asset:   saved.ID,
				Action:  defs.MappingActionTitle[body.Action],
				Created: nowTimestamp,
				Creator: creator,
				Comment: body.Reason,
			}
			history.GenID()
			if err = inst.elastic.Enduser().AssetHistory().Store(context.Background(), history); err != nil {
				inst.logger.Errorf("failed to store asset history (%s), reason: %v", history.ID, err)
				return
			}
		}

		if err = inst.kafka.SendChangeAsset(&oldAsset, saved, kafkaAction); err != nil {
			inst.logger.Errorf("failed to SendChangeAsset, reason: %v", err)
			return
		}
	})
	defer p.Release()
	for _, id := range body.IDs {
		wg.Add(1)
		if err = p.Invoke(id); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	wg.Wait()
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Go()
}

func (inst *AssetHandler) History(c echo.Context) error {
	body, err := inst.verifyHistory(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	query := body.Query()
	results, err := inst.elastic.Enduser().AssetHistory().Find(context.Background(), query, []string{"-created"}, body.Offset, body.Size)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
	}
	count, err := inst.elastic.Enduser().AssetHistory().Count(context.Background(), query)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": results, "total": count}).Go()
}

func (inst *AssetHandler) verifyAction(c echo.Context) (body model.RequestAssetAction, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	ids := make([]string, 0)
	for _, id := range body.IDs {
		id = strings.ToLower(strings.TrimSpace(id))
		if len(id) > 0 {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return body, errors.New("invalid value for parameter <ids>")
	}
	body.IDs = ids
	body.Action = strings.ToLower(strings.TrimSpace(body.Action))
	if !slice.String(defs.EnumAction).Contains(body.Action) {
		return body, errors.New("invalid value for parameter <action>")
	}
	body.Reason = strings.TrimSpace(body.Reason)
	// Success
	return body, nil
}

func (inst *AssetHandler) verifyHistory(c echo.Context) (body model.RequestAssetHistory, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.ID = strings.ToLower(strings.TrimSpace(body.ID))
	if body.Size == 0 {
		body.Size = 10
	}
	// Success
	return body, nil
}
