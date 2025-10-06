package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/labstack/echo/v4"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic/db"
	es "gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic/exception"
	mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/awesome-threat/library/slice"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/sync/errgroup"

	es7 "github.com/elastic/go-elasticsearch/v7"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/adapter/elastic"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/helper"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

type AssetDomainIPAddressHandler struct {
	name          string
	logger        pencil.Logger
	client        *resty.Client
	elastic       elastic.GlobalRepository
	mongo         mongo.GlobalRepository
	lock          *sync.Mutex
	organizations map[string]string
	config        model.Config
	esClient      *es7.Client
	kafka         *KafkaHandler
}

func NewAssetDomainIPAddressHandler(conf model.Config, esClient *es7.Client, kafka *KafkaHandler) AssetDomainIPAddressInterface {
	handler := AssetDomainIPAddressHandler{name: defs.HandlerAssetDomainIPAddress, lock: &sync.Mutex{}, config: conf}
	handler.logger, _ = pencil.New(handler.name, pencil.DebugLevel, true, os.Stdout)
	handler.client = resty.New().SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).SetTimeout(time.Duration(defs.DefaultApiTimeout))
	handler.elastic = elastic.NewGlobalRepository(conf.Adapter.Elastic)
	handler.mongo = mongo.NewGlobalRepository(conf.Adapter.Mongo)
	handler.collectOrganizations()
	handler.esClient = esClient
	handler.kafka = kafka
	// Success
	return &handler
}

func (inst *AssetDomainIPAddressHandler) GetTags(c echo.Context) error {
	filter := make([]interface{}, 0)
	filter = append(filter, map[string]interface{}{
		"term": map[string]interface{}{
			"visible": true,
		},
	})
	filter = append(filter, map[string]interface{}{
		"terms": map[string]interface{}{
			"type": defs.EnumAssetDomainIPAddressType,
		},
	})
	query := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": filter,
			},
		},
		"size": 0,
		"aggs": map[string]interface{}{
			"tags_count": map[string]interface{}{
				"terms": map[string]interface{}{
					"field": "tags",
					"size":  10000,
				},
			},
		},
	}
	body := new(bytes.Buffer)
	err := json.NewEncoder(body).Encode(query)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	doc, err := inst.esClient.Search(
		inst.esClient.Search.WithBody(body),
		inst.esClient.Search.WithIndex(inst.config.Adapter.Elastic.Index.TIAsset),
	)
	defer doc.Body.Close()
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	if doc.IsError() {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(doc.String()).Go()
	}
	var res model.AggregationResult
	if err := json.NewDecoder(doc.Body).Decode(&res); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}

	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": res.Aggregation["tags_count"].Buckets}).Go()
}

func (inst *AssetDomainIPAddressHandler) Search(c echo.Context) error {
	body, err := inst.verifySearch(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	query := body.Query()
	documents, err := inst.elastic.Enduser().Asset().Find(context.Background(), query, body.Sorts, body.Offset, body.Size)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
	}
	inst.lock.Lock()
	for _, document := range documents {
		// Organization
		if name, ok := inst.organizations[document.Organization]; ok {
			document.Organization = name
		}
	}
	inst.lock.Unlock()
	count, err := inst.elastic.Enduser().Asset().Count(context.Background(), query)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": documents, "total": count}).Go()

}

func (inst *AssetDomainIPAddressHandler) Statistic(c echo.Context) error {
	body, err := inst.verifyStatistic(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	filter := make([]interface{}, 0)
	filter = append(filter, map[string]interface{}{
		"bool": map[string]interface{}{
			"must_not": []interface{}{
				map[string]interface{}{
					"term": map[string]interface{}{
						"status": defs.AssetStatusCodeUnknown,
					},
				},
			},
		},
	})
	should := make([]interface{}, 0)
	for _, kind := range defs.EnumAssetDomainIPAddressType {
		should = append(should, map[string]interface{}{
			"term": map[string]interface{}{
				"type": kind,
			},
		})
	}
	filter = append(filter, map[string]interface{}{
		"bool": map[string]interface{}{
			"should": should,
		},
	})
	filter = append(filter, map[string]interface{}{
		"term": map[string]interface{}{
			"visible": true,
		},
	})
	if body.Creator != "" {
		filter = append(filter, map[string]interface{}{
			"term": map[string]interface{}{
				"creator": body.Creator,
			},
		})
	}
	if len(body.Tags) > 0 {
		filter = append(filter, map[string]interface{}{
			"terms": map[string]interface{}{
				"tags": body.Tags,
			},
		})
	}
	query := map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": filter,
		},
	}
	// if len(body)
	common, err := inst.elastic.Enduser().Asset().AggregationCount(context.Background(), query, []string{"creator", "type", "active", "status"})
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	result := map[string]interface{}{}
	// Creator
	creators := make([]db.ResultAggregationCount, 0)
	for _, creator := range common["creator"] {
		if creator.Value != "Unknown" && creator.Value != "" {
			creators = append(creators, creator)
		}
	}
	result["creator"] = creators
	// Type
	types := make([]db.ResultAggregationCount, len(defs.EnumAssetDomainIPAddressType))
	types[0].Value = defs.AssetTypeIPv4
	types[1].Value = defs.AssetTypeIPv6
	types[2].Value = defs.AssetTypeIPv4Network
	types[3].Value = defs.AssetTypeIPv6Network
	types[4].Value = defs.AssetTypeDomain
	for _, kind := range common["type"] {
		switch kind.Value.(string) {
		case defs.AssetTypeIPv4:
			types[0].Count = kind.Count
		case defs.AssetTypeIPv6:
			types[1].Count = kind.Count
		case defs.AssetTypeIPv4Network:
			types[2].Count = kind.Count
		case defs.AssetTypeIPv6Network:
			types[3].Count = kind.Count
		case defs.AssetTypeDomain:
			types[4].Count = kind.Count
		}
	}
	result["type"] = types
	// Active
	active := make([]db.ResultAggregationCount, len(defs.MappingAssetActive))
	active[0].Value = defs.AssetActive
	active[1].Value = defs.AssetInactive
	for _, act := range common["active"] {
		switch act.Value.(float64) {
		case 1:
			active[0].Count = act.Count
		case 0:
			active[1].Count = act.Count
		}
	}
	result["active"] = active
	// Status
	status := make([]db.ResultAggregationCount, len(defs.MappingAssetStatus))
	status[0].Value = defs.AssetStatusCodeNew
	status[1].Value = defs.AssetStatusCodeApproved
	status[2].Value = defs.AssetStatusCodeReject
	for _, s := range common["status"] {
		switch s.Value.(float64) {
		case defs.AssetStatusCodeNew:
			status[0].Count = s.Count
		case defs.AssetStatusCodeApproved:
			status[1].Count = s.Count
		case defs.AssetStatusCodeReject:
			status[2].Count = s.Count
		}
	}
	result["status"] = status
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(result).Go()
}

func (inst *AssetDomainIPAddressHandler) Create(c echo.Context) error {
	ctx := context.Background()
	creator := c.Get("user_name").(string)
	body, err := inst.verifyCreate(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	now, _ := clock.Now(clock.Local)
	nowTimestamp := clock.UnixMilli(now)
	docs := body.Generate(creator)
	documents := make([]*model.Asset, 0)
	histories := make([]*model.AssetHistory, 0)
	success := 0
	duplicate := 0
	fail := 0
	for _, doc := range docs {
		if helper.IsIpPrivate(doc.Value) {
			continue
		}
		if saved, err := inst.elastic.Enduser().Asset().GetByID(context.Background(), doc.ID); err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			documents = append(documents, doc)
			success += 1
			history := &model.AssetHistory{
				Asset:   doc.ID,
				Action:  defs.TitleActionCreate,
				Created: nowTimestamp,
				Creator: creator,
			}
			history.GenID()
			histories = append(histories, history)
		} else {
			if !saved.Visible {
				saved.Visible = true
				saved.Active = doc.Active
				saved.Status = doc.Status
				saved.Tags = doc.Tags
				documents = append(documents, saved)
				success += 1
				history := &model.AssetHistory{
					Asset:   doc.ID,
					Action:  defs.TitleActionCreate,
					Created: nowTimestamp,
					Creator: creator,
				}
				history.GenID()
				histories = append(histories, history)
			} else {
				duplicate += 1
			}
		}
	}
	groupUser, err := inst.mongo.Account().GroupUser().Get(ctx, body.Organization)
	if err != nil {
		if err.Error() != mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		groupUser = &model.GroupUser{}
	}
	if groupUser.Role != "" {
		role, err := inst.mongo.Account().Roles().GetByName(ctx, groupUser.Role)
		if err != nil {
			if err.Error() != mg.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			role = &model.Role{}
		}
		// Check mass
		if role.Mass {
			if role.LimitAssetIPDomain >= 0 {
				query := map[string]interface{}{
					"bool": map[string]interface{}{
						"filter": []interface{}{
							map[string]interface{}{
								"term": map[string]interface{}{
									"visible": true,
								},
							},
							map[string]interface{}{
								"term": map[string]interface{}{
									"organization": body.Organization,
								},
							},
							map[string]interface{}{
								"terms": map[string]interface{}{
									"type": []string{defs.AssetTypeDomain, defs.AssetTypeIPv4, defs.AssetTypeIPv6, defs.AssetTypeIPv4Network, defs.AssetTypeIPv6Network},
								},
							},
						},
					},
				}
				totalAssets, err := inst.elastic.Enduser().Asset().Count(ctx, query)
				if err != nil {
					return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
				}
				if success+int(totalAssets) > role.LimitAssetIPDomain {
					return rest.JSON(c).Code(rest.StatusBadRequest).Log(errors.New(defs.ErrLimitAsset)).Go()
				}
			}
		}
	}
	fail = len(body.Assets) - success - duplicate
	if err = inst.elastic.Enduser().Asset().StoreAll(context.Background(), documents); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	if len(histories) > 0 {
		if err := inst.elastic.Enduser().AssetHistory().StoreAll(context.Background(), histories); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	for _, doc := range documents {
		if err = inst.kafka.SendChangeAsset(nil, doc, defs.TitleActionCreate); err != nil {
			inst.logger.Errorf("failed to SendChangeAsset, reason: %v", err)
		}
	}

	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]int{"success": success, "duplicate": duplicate, "fail": fail}).Go()
}

func (inst *AssetDomainIPAddressHandler) Edit(c echo.Context) error {
	creator := c.Get("user_name").(string)
	body, err := inst.verifyEdit(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	// Update
	now, _ := clock.Now(clock.Local)
	nowTimestamp := clock.UnixMilli(now)
	saved, err := inst.elastic.Enduser().Asset().GetByID(context.Background(), body.ID)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusNotFound).Log(err).Go()
	}
	oldAsset := *saved
	if !slice.String(defs.EnumAssetDomainIPAddressType).Contains(saved.Type) {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(fmt.Errorf("asset type must be ipv4, ipv6, ipv4-network, ipv6-network")).Go()
	}
	if body.Organization != "" && saved.Organization != body.Organization {
		return rest.JSON(c).Code(rest.StatusForbidden).Go()
	}
	if helper.GetAssetType(body.Asset) != saved.Type {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(fmt.Errorf("invalid value for parameter <asset>")).Go()
	}
	saved.Title = body.Asset
	saved.Value = body.Asset
	saved.Modified = nowTimestamp
	saved.Attribute = model.GenerateDomainIPAddressAttribute(saved.Type, saved.Value)
	saved.Tags = body.Tags
	oldID := saved.ID
	saved.GenID()
	// Check conflict
	if oldID != saved.ID {
		if _, err := inst.elastic.Enduser().Asset().GetByID(context.Background(), saved.ID); err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
		} else {
			return rest.JSON(c).Code(rest.StatusConflict).Go()
		}
	}
	histories := make([]*model.AssetHistory, 0)
	// Change status
	kafkaAction := defs.TitleActionEdit
	if saved.Status != body.Status && body.Status != defs.AssetStatusCodeUnknown {
		history := &model.AssetHistory{
			Created: nowTimestamp,
			Creator: creator,
		}
		switch body.Status {
		case defs.AssetStatusCodeApproved:
			history.Action = defs.TitleActionApprove
			histories = append(histories, history)
			kafkaAction = defs.TitleActionApprove
		case defs.AssetStatusCodeReject:
			history.Action = defs.TitleActionReject
			histories = append(histories, history)
		}
		saved.Status = body.Status
	}
	// Change active
	if body.Active != "" {
		active := defs.MappingAssetActive[body.Active]
		if saved.Active != active {
			history := &model.AssetHistory{
				Created: nowTimestamp,
				Creator: creator,
			}
			if active {
				history.Action = defs.TitleActionActive
			} else {
				history.Action = defs.TitleActionDeactive
			}
			histories = append(histories, history)
			saved.Active = active
		}
	}
	// Saved History
	histories = append(histories, &model.AssetHistory{
		Action:  defs.TitleActionEdit,
		Created: nowTimestamp,
		Creator: creator,
	})
	for _, history := range histories {
		history.Asset = saved.ID
		history.GenID()
	}
	if err = inst.elastic.Enduser().AssetHistory().StoreAll(context.Background(), histories); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Saved document
	if err = inst.elastic.Enduser().Asset().Store(context.Background(), saved); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	// Delete old document
	if oldID != saved.ID {
		// Asset
		if err = inst.elastic.Enduser().Asset().DeleteByID(context.Background(), oldID); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		// History
		oldHistories, err := inst.elastic.Enduser().AssetHistory().FindAll(context.Background(), map[string]interface{}{"term": map[string]interface{}{"asset": oldID}}, []string{})
		if err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			oldHistories = make([]*model.AssetHistory, 0)
		}
		newHistories := make([]*model.AssetHistory, 0)
		for _, history := range oldHistories {
			if err = inst.elastic.Enduser().AssetHistory().DeleteByID(context.Background(), history.ID); err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			history.Asset = saved.ID
			history.GenID()
			newHistories = append(newHistories, history)
		}
		if err = inst.elastic.Enduser().AssetHistory().StoreAll(context.Background(), newHistories); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	if err = inst.kafka.SendChangeAsset(&oldAsset, saved, kafkaAction); err != nil {
		inst.logger.Errorf("failed to SendChangeAsset, reason: %v", err)
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(saved.ID).Go()
}

func (inst *AssetDomainIPAddressHandler) Validate(c echo.Context) error {
	body, err := inst.verifyValue(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(helper.GetAssetType(body.Asset)).Go()
}

func (inst *AssetDomainIPAddressHandler) Delete(c echo.Context) error {
	creator := c.Get("user_name").(string)
	body, err := inst.verifyDelete(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	now, _ := clock.Now(clock.Local)
	nowTimestamp := clock.UnixMilli(now)
	histories := make([]*model.AssetHistory, 0)
	for _, id := range body.IDs {
		saved, err := inst.elastic.Enduser().Asset().GetByID(context.Background(), id)
		oldAsset := *saved
		if err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			continue
		}
		saved.Visible = false
		saved.Modified = nowTimestamp
		saved.Tags = nil
		if err := inst.elastic.Enduser().Asset().Update(context.Background(), saved); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		history := &model.AssetHistory{
			Asset:   id,
			Action:  defs.TitleActionDelete,
			Created: clock.UnixMilli(now),
			Creator: creator,
		}
		history.GenID()
		histories = append(histories, history)
		if err = inst.kafka.SendChangeAsset(&oldAsset, saved, defs.TitleActionDelete); err != nil {
			inst.logger.Errorf("failed to SendChangeAsset, reason: %v", err)
		}
	}
	if err = inst.elastic.Enduser().AssetHistory().StoreAll(context.Background(), histories); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	return rest.JSON(c).Code(rest.StatusOK).Go()
}

func (inst *AssetDomainIPAddressHandler) Upload(c echo.Context) error {
	panic("implement me")
}

func (inst *AssetDomainIPAddressHandler) Import(c echo.Context) error {
	panic("implement me")
}

func (inst *AssetDomainIPAddressHandler) Exist(c echo.Context) error {
	body, err := inst.verifyDomainIPAddress(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	exists := make([]string, 0)
	assets := make([]*model.AssetSummary, 0)
	for _, asset := range body.Assets {
		if helper.IsIpPrivate(asset) {
			assets = append(assets, &model.AssetSummary{
				Value: asset,
				Type:  defs.AssetTypeIpPrivate,
			})
			continue
		}
		kind := helper.GetAssetType(asset)
		if kind != "" {
			assets = append(assets, &model.AssetSummary{
				Value: asset,
				Type:  kind,
			})
			id := hash.SHA1(fmt.Sprintf("%s--%s--%s", body.Organization, kind, asset))
			if saved, err := inst.elastic.Enduser().Asset().GetByID(context.Background(), id); err != nil {
				if err.Error() != es.NotFoundError {
					return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
				}
			} else {
				if saved.Visible == true {
					exists = append(exists, asset)
				}
			}
		} else {
			assets = append(assets, &model.AssetSummary{
				Value: asset,
				Type:  defs.AssetTypeUnknown,
			})
		}
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"exist": exists, "total": len(body.Assets), "asset": assets}).Go()

}

func (inst *AssetDomainIPAddressHandler) Owner(c echo.Context) error {
	body, err := inst.verifyValue(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	query := body.Query()
	if query == nil {
		return rest.JSON(c).Code(rest.StatusOK).Body("").Go()
	}
	assets, err := inst.elastic.Enduser().Asset().FindAll(context.Background(), query, []string{})
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusOK).Body("").Go()
	}
	kind := helper.GetAssetType(body.Asset)
	for _, asset := range assets {
		switch kind {
		case defs.AssetTypeDomain:
			if asset.Value == body.Asset {
				return rest.JSON(c).Code(rest.StatusOK).Body(asset.Organization).Go()
			}
		case defs.AssetTypeIPv4, defs.AssetTypeIPv6:
			switch asset.Type {
			case defs.AssetTypeIPv4, defs.AssetTypeIPv6:
				if asset.Value == body.Asset {
					return rest.JSON(c).Code(rest.StatusOK).Body(asset.Organization).Go()
				}
			case defs.AssetTypeIPv4Network, defs.AssetTypeIPv6Network:
				_, cidr, err := net.ParseCIDR(asset.Value)
				if err == nil {
					ip := net.ParseIP(body.Asset)
					if ip != nil && cidr.Contains(ip) && !strings.Contains(asset.Value, "/0") {
						return rest.JSON(c).Code(rest.StatusOK).Body(asset.Organization).Go()
					}
				}
			}
		case defs.AssetTypeIPv4Network, defs.AssetTypeIPv6Network:
			if asset.Value == body.Asset {
				return rest.JSON(c).Code(rest.StatusOK).Body(asset.Organization).Go()
			}
		}
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body("").Go()
}

func (inst *AssetDomainIPAddressHandler) Synchronize(c echo.Context) error {
	panic("implement me")
}

func (inst *AssetDomainIPAddressHandler) verifyDomainIPAddress(c echo.Context) (body model.RequestAssetDomainIPAddress, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	assets := make([]string, 0)
	for _, asset := range body.Assets {
		if asset != "" {
			assets = append(assets, strings.ToLower(strings.TrimSpace(asset)))
		}
	}
	body.Assets = assets
	// Success
	return body, nil
}

func (inst *AssetDomainIPAddressHandler) conformTags(tags []string) []string {
	rows := make([]string, len(tags))
	for i, tag := range tags {
		row := strings.TrimSpace(tag)
		row = strings.ToLower(row)
		rows[i] = row
	}
	return rows
}

func (inst *AssetDomainIPAddressHandler) verifySearch(c echo.Context) (body model.RequestAssetDomainIPAddressSearch, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.Tags = inst.conformTags(body.Tags)
	if body.Organization != "" {
		body.Organization = strings.ToLower(body.Organization)
	}
	if body.Keyword != "" {
		body.Keyword = strings.ToLower(body.Keyword)
		keywords := make([]string, 0)
		for _, kw := range strings.Fields(body.Keyword) {
			keywords = append(keywords, regexp.QuoteMeta(kw))
		}
		body.Keyword = strings.Join(keywords, "*")
	}
	if len(body.Type) > 0 {
		for _, t := range body.Type {
			t = strings.ToLower(t)
			if !slice.String(defs.EnumAssetDomainIPAddressType).Contains(t) {
				return body, errors.New("invalid value for parameter <type>")
			}
		}
	} else {
		body.Type = defs.EnumAssetDomainIPAddressType
	}
	if body.Active != "" {
		body.Active = strings.ToLower(body.Active)
		if _, ok := defs.MappingAssetActive[body.Active]; !ok {
			return body, errors.New("invalid value for parameter <active>")
		}
	}
	if len(body.Status) > 0 {
		for _, status := range body.Status {
			if _, ok := defs.MappingAssetStatus[status]; !ok {
				return body, errors.New("invalid value for parameter <status>")
			}
		}
	}
	if len(body.Sorts) == 0 {
		body.Sorts = []string{"-modified"}
	}
	if body.Size == 0 {
		body.Size = 20
	}
	// Success
	return body, nil
}

func (inst *AssetDomainIPAddressHandler) verifyStatistic(c echo.Context) (body model.RequestAssetDomainIPAddressStatistic, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.Tags = inst.conformTags(body.Tags)
	// Success
	return body, nil
}

func (inst *AssetDomainIPAddressHandler) verifyCreate(c echo.Context) (body model.RequestAssetDomainIPAddressCreate, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.Tags = inst.conformTags(body.Tags)
	if body.Organization == "" {
		return body, errors.New("invalid value for parameter <organization>")
	}
	body.Tags = helper.UniqArray(body.Tags)
	assets := make([]string, 0)
	for _, asset := range body.Assets {
		if asset != "" {
			assets = append(assets, strings.ToLower(strings.TrimSpace(asset)))
		}
	}
	body.Assets = assets
	if len(body.Assets) == 0 {
		return body, errors.New("invalid value for parameter <assets>")
	}
	body.Assets = slice.String(body.Assets).Unique().Extract()
	// Success
	return body, nil
}

func (inst *AssetDomainIPAddressHandler) verifyEdit(c echo.Context) (body model.RequestAssetDomainIPAddressEdit, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.Tags = inst.conformTags(body.Tags)
	body.Tags = helper.UniqArray(body.Tags)
	body.Asset = strings.ToLower(strings.TrimSpace(body.Asset))
	if body.Active != "" {
		body.Active = strings.ToLower(body.Active)
		if _, ok := defs.MappingAssetActive[body.Active]; !ok {
			return body, errors.New("invalid value for parameter <active>")
		}
	}
	if body.Status != 0 {
		if _, ok := defs.MappingAssetStatus[body.Status]; !ok {
			return body, errors.New("invalid value for parameter <status>")
		}
	}
	// Success
	return body, nil
}

func (inst *AssetDomainIPAddressHandler) verifyValue(c echo.Context) (body model.RequestAssetDomainIPAddressValue, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.Asset = strings.ToLower(strings.TrimSpace(body.Asset))
	// Success
	return body, nil
}

func (inst *AssetDomainIPAddressHandler) verifyDelete(c echo.Context) (body model.RequestAssetDomainIPAddressDelete, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	ids := make([]string, 0)
	for _, id := range body.IDs {
		ids = append(ids, strings.ToLower(strings.TrimSpace(id)))
	}
	if len(ids) == 0 {
		return body, errors.New("invalid value for parameter <ids>")
	}
	body.IDs = ids
	// Success
	return body, nil
}

func (inst *AssetDomainIPAddressHandler) collectOrganizations() {
	group, _ := errgroup.WithContext(context.Background())
	group.Go(func() error {
		for {
			orgs, err := inst.mongo.Account().GroupUser().FindAll(context.Background(), &bson.M{}, []string{})
			if err != nil {
				inst.logger.Errorf("failed to get group user, reason: %v", err)
				clock.Sleep(clock.Second * 5)
				continue
			}
			results := map[string]string{}
			if len(orgs) > 0 {
				inst.lock.Lock()
				for _, org := range orgs {
					results[org.TenantID] = org.Name
				}
				inst.organizations = results
				inst.lock.Unlock()
			}
			// Sleep
			clock.Sleep(clock.Second * 10)
		}
	})
}
