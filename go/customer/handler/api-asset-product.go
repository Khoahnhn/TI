package handler

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/thedatashed/xlsxreader"
	"github.com/xuri/excelize/v2"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic/db"
	es "gitlab.viettelcyber.com/awesome-threat/library/adapter/elastic/exception"
	mg "gitlab.viettelcyber.com/awesome-threat/library/adapter/mongo"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/rabbit"
	"gitlab.viettelcyber.com/awesome-threat/library/adapter/redis"
	"gitlab.viettelcyber.com/awesome-threat/library/clock"
	"gitlab.viettelcyber.com/awesome-threat/library/core/cpe"
	"gitlab.viettelcyber.com/awesome-threat/library/hash"
	"gitlab.viettelcyber.com/awesome-threat/library/log/pencil"
	"gitlab.viettelcyber.com/awesome-threat/library/rest"
	"gitlab.viettelcyber.com/awesome-threat/library/slice"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/adapter/elastic"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/adapter/mongo"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/defs"
	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/sync/errgroup"
)

type AssetProductHandler struct {
	name          string
	logger        pencil.Logger
	client        *resty.Client
	elastic       elastic.GlobalRepository
	mongo         mongo.GlobalRepository
	queue         rabbit.Service
	lock          *sync.Mutex
	organizations map[string]string
	kafka         *KafkaHandler
	config        model.Config
	//lru            cache.Cache
	cache          redis.Service
	importTemplate xlsxreader.Row
	mu             sync.Mutex
	wg             sync.WaitGroup
}

const (
	importTemplateFilePath      = "static/template_asset.xlsx"
	importErrorTemplateFilePath = "static/template_asset_error.xlsx"
)

type handleImportMsg struct {
	Documents     []*model.Asset           `json:"documents"`
	Duplicate     int64                    `json:"duplicate"`
	Success       int64                    `json:"success"`
	SuccessDetail []map[string]interface{} `json:"success_detail"`
	Fail          []map[string]interface{} `json:"fail"`
	FileError     []string                 `json:"file_error"`
	ReportID      string                   `json:"report_id"`
}

func (t *handleImportMsg) mappingCells() map[string]string {
	return map[string]string{
		"A": "index",
		"B": "owner",
		"C": "product_type",
		"D": "product",
		"E": "version",
		"F": "update",
		"G": "note",
	}
}
func (t *handleImportMsg) responseFailDetails() []map[string]interface{} {
	out := make([]map[string]interface{}, 0)
	for id, v := range t.Fail {
		if id >= 20 {
			break
		}
		item := map[string]interface{}{
			"index":        "",
			"owner":        "",
			"product_type": "",
			"product":      "",
			"version":      "",
			"update":       "",
			"note":         "",
		}
		for col, value := range v {
			if key, ok := t.mappingCells()[string(col[0])]; ok {
				item[key] = value
			}
		}
		out = append(out, item)
	}
	return out
}

func NewAssetProductHandler(conf model.Config, kafka *KafkaHandler) *AssetProductHandler {
	handler := AssetProductHandler{name: defs.HandlerAssetProduct, lock: &sync.Mutex{}, config: conf}
	handler.logger, _ = pencil.New(handler.name, pencil.DebugLevel, true, os.Stdout)
	handler.client = resty.New().SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).SetTimeout(time.Duration(defs.DefaultApiTimeout))
	handler.elastic = elastic.NewGlobalRepository(conf.Adapter.Elastic)
	handler.mongo = mongo.NewGlobalRepository(conf.Adapter.Mongo)
	handler.queue = rabbit.NewService(conf.Adapter.Rabbit.Crawler, nil)
	handler.kafka = kafka
	handler.collectOrganizations()
	//handler.lru = cache.NewMemCache(10, 30*time.Minute)
	handler.cache = redis.NewService(handler.config.Adapter.Redis.Cache, nil)
	fData, err := ioutil.ReadFile(importTemplateFilePath)
	if err != nil {
		log.Error(err)
		return &handler
	}
	excel, err := xlsxreader.NewReader(fData)
	if err != nil {
		log.Error(err)
		return nil
	}
	for row := range excel.ReadRows(excel.Sheets[0]) {
		if row.Index == 3 {
			handler.importTemplate = row
		}
	}

	// latest recent usage 10 items in 30 minutes
	// Success
	return &handler
}

func (inst *AssetProductHandler) Search(c echo.Context) error {
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
		attribute, err := document.GetProductAttribute()
		if err != nil {
			inst.lock.Unlock()
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		// Vendor
		attribute.Vendor = strings.ReplaceAll(attribute.Vendor, "-", "_")
		vendorPath := strings.Split(attribute.Vendor, "_")
		vendorVerbose := make([]string, 0)
		for _, v := range vendorPath {
			vendorVerbose = append(vendorVerbose, strings.Title(strings.ToLower(v)))
		}
		attribute.Vendor = strings.Join(vendorVerbose, " ")
		// Product
		attribute.Product = strings.ReplaceAll(attribute.Product, "-", "_")
		productPath := strings.Split(attribute.Product, "_")
		productVerbose := make([]string, 0)
		for _, v := range productPath {
			productVerbose = append(productVerbose, strings.Title(strings.ToLower(v)))
		}
		attribute.Product = strings.Join(productVerbose, " ")
		// Success
		document.Attribute = attribute
	}
	inst.lock.Unlock()
	count, err := inst.elastic.Enduser().Asset().Count(context.Background(), query)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": make([]interface{}, 0), "total": 0}).Go()
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"data": documents, "total": count}).Go()
}

func (inst *AssetProductHandler) Statistic(c echo.Context) error {
	body, err := inst.verifyStatistic(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	filter := make([]interface{}, 0)
	filter = append(filter,
		map[string]interface{}{
			"term": map[string]interface{}{
				"type": defs.AssetTypeProduct,
			},
		},
		map[string]interface{}{
			"bool": map[string]interface{}{
				"must_not": []interface{}{
					map[string]interface{}{
						"term": map[string]interface{}{
							"status": defs.AssetStatusCodeUnknown,
						},
					},
				},
			},
		},
	)
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
	query := map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": filter,
		},
	}
	common, err := inst.elastic.Enduser().Asset().AggregationCount(context.Background(), query, []string{"creator", "attribute.product_part", "active"})
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
	// Part
	parts := make([]db.ResultAggregationCount, len(defs.MappingProductPart))
	parts[0].Value = defs.ProductPartCodeApplication
	parts[1].Value = defs.ProductPartCodeOperation
	parts[2].Value = defs.ProductPartCodeHardware
	for _, part := range common["attribute.product_part"] {
		switch part.Value.(string) {
		case defs.ProductPartCodeApplication:
			parts[0].Count = part.Count
		case defs.ProductPartCodeOperation:
			parts[1].Count = part.Count
		case defs.ProductPartCodeHardware:
			parts[2].Count = part.Count
		}
	}
	result["part"] = parts
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
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(result).Go()
}

func (inst *AssetProductHandler) Create(c echo.Context) error {
	ctx := context.Background()
	creator := c.Get("user_name").(string)
	body, err := inst.verifyCreate(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	docs := body.Generate(creator)
	documents := make([]*model.Asset, 0)
	histories := make([]*model.AssetHistory, 0)
	now, _ := clock.Now(clock.Local)
	nowTimestamp := clock.UnixMilli(now)
	success := 0
	duplicate := 0
	inst.logger.Debugf("Len docs: %d", len(docs))
	ids := []string{}

	for _, doc := range docs {
		inst.logger.Debugf("doc: %v", doc)
		ids = append(ids, doc.ID)
		if saved, err := inst.elastic.Enduser().Asset().GetByID(context.Background(), doc.ID); err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			inst.logger.Debug("Asset not found. So create the new asset.")
			documents = append(documents, doc)
			success++
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
				inst.logger.Debug("Asset found. So change active and visible.")
				saved.Visible = true
				saved.Active = true
				saved.Status = defs.AssetStatusCodeApproved
				documents = append(documents, saved)
				success++
				history := &model.AssetHistory{
					Asset:   doc.ID,
					Action:  defs.TitleActionCreate,
					Created: nowTimestamp,
					Creator: creator,
				}
				history.GenID()
				histories = append(histories, history)
			} else {
				duplicate++
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
			if role.LimitAssetProduct >= 0 {
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
									"type": []string{defs.AssetTypeProduct},
								},
							},
						},
					},
				}
				totalAssets, err := inst.elastic.Enduser().Asset().Count(ctx, query)
				if err != nil {
					return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
				}
				if success+int(totalAssets) > role.LimitAssetProduct {
					return rest.JSON(c).Code(rest.StatusBadRequest).Log(errors.New(defs.ErrLimitAsset)).Go()
				}
			}
		}
	}
	if err = inst.elastic.Enduser().Asset().StoreAll(context.Background(), documents); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	inst.logger.Debugf("Len documents: %d", len(documents))
	if len(documents) > 0 {
		msg := &model.ProductMapping{Organization: documents[0].Organization}
		assets := make([]string, 0)
		for _, document := range documents {
			assets = append(assets, document.Value)
		}
		msg.Assets = assets
		bts, err := json.Marshal(msg)
		if err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		if err = inst.queue.Publish("", defs.QueueCveMapping, rabbit.Message{
			Body:        bts,
			ContentType: rabbit.MIMEApplicationJSON,
			Mode:        rabbit.Persistent,
		}); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	if err := inst.elastic.Enduser().AssetHistory().StoreAll(context.Background(), histories); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}

	// Send event to kafka for mapping CVE
	for _, doc := range documents {
		if err = inst.kafka.SendChangeAsset(nil, doc, defs.TitleActionCreate); err != nil {
			inst.logger.Errorf("failed to Kafka asset product event, reason: %v", err)
		}
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(ids).Go()
}

func (inst *AssetProductHandler) Edit(c echo.Context) error {
	body, err := inst.verifyEdit(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	now, _ := clock.Now(clock.Local)
	saved, err := inst.elastic.Enduser().Asset().GetByID(context.Background(), body.ID)
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		return rest.JSON(c).Code(rest.StatusNotFound).Log(err).Go()
	}
	if saved.Type != defs.AssetTypeProduct {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(fmt.Errorf("asset type must be product")).Go()
	}
	if body.Organization != "" && saved.Organization != body.Organization {
		return rest.JSON(c).Code(rest.StatusForbidden).Go()
	}

	oldAsset := saved.Clone()

	saved.Title = body.Product
	saved.Value = body.Product
	saved.Modified = clock.UnixMilli(now)
	if body.Active != "" {
		saved.Active = defs.MappingAssetActive[body.Active]
	}
	saved.Status = body.Status

	pro, _ := cpe.NewItemFromFormattedString(body.Product)
	attr, err := saved.GetProductAttribute()
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	attr.Vendor = pro.Vendor().String()
	attr.Part = pro.Part().String()
	attr.Product = pro.Product().String()
	attr.Version = pro.Version().String()
	attr.Update = pro.Update().String()
	saved.Attribute = attr
	oldID := saved.ID
	saved.GenID()
	if err = inst.elastic.Enduser().Asset().Store(context.Background(), saved); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	if oldID != saved.ID {
		// Delete
		if err = inst.elastic.Enduser().Asset().DeleteByID(context.Background(), oldID); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}

	// Send event to kafka for mapping CVE
	// Just for tobe approved assets
	inst.logger.Debugf("Old status: %v", oldAsset.Status)
	inst.logger.Debugf("New status: %v", saved.Status)
	if oldAsset.Status != defs.AssetStatusCodeApproved &&
		saved.Status == defs.AssetStatusCodeApproved {

		if err = inst.kafka.SendChangeAsset(oldAsset, saved, defs.TitleActionApprove); err != nil {
			inst.logger.Errorf("failed to Kafka asset product event, reason: %v", err)
		}
	}

	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(saved.ID).Go()
}

func (inst *AssetProductHandler) Delete(c echo.Context) error {
	body, err := inst.verifyProductIDs(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	success := make([]string, 0)
	for _, id := range body.IDs {
		saved, err := inst.elastic.Enduser().Asset().GetByID(context.Background(), id)
		if err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			continue
		}
		if body.Organization != "" && saved.Organization != body.Organization {
			return rest.JSON(c).Code(rest.StatusForbidden).Go()
		}
		// Visible
		saved.Visible = false
		if err = inst.elastic.Enduser().Asset().Update(context.Background(), saved); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
		success = append(success, id)
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(success).Go()
}

func (inst *AssetProductHandler) Upload(c echo.Context) error {
	panic("implement me")
}

func (inst *AssetProductHandler) Exist(c echo.Context) error {
	body, err := inst.verifyProducts(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	exists := make([]string, 0)
	for _, product := range body.Products {
		id := hash.SHA1(fmt.Sprintf("%s--%s--%s", body.Organization, defs.AssetTypeProduct, product))
		if saved, err := inst.elastic.Enduser().Asset().GetByID(context.Background(), id); err != nil {
			if err.Error() != es.NotFoundError {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
		} else {
			if saved.Visible == true {
				exists = append(exists, product)
			}
		}
	}
	// Success
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{"exist": exists, "total": len(body.Products)}).Go()
}

func (inst *AssetProductHandler) Synchronize(c echo.Context) error {
	body, err := inst.verifySynchronize(c)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusOK).Log(err).Go()
	}
	// Get asset popular
	res, err := inst.client.R().
		SetHeader(rest.HeaderContentType, rest.MIMEApplicationJSON).
		SetBody(map[string]interface{}{"size": -1}).
		Post(fmt.Sprintf(defs.UriSearchCPEPopular, inst.config.Api.Threat))
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	var response model.ResponseSearchCPEPopular
	if err = json.Unmarshal(res.Body(), &response); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}
	orgs, err := inst.mongo.Account().GroupUser().FindAll(context.Background(), &bson.M{}, []string{})
	if err != nil {
		if err.Error() != mg.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	assets := make([]*model.Asset, 0)
	assetIDs := make([]string, 0)
	for _, popular := range response.Detail.Data {
		for _, org := range orgs {
			pro, _ := cpe.NewItemFromFormattedString(popular.Value)
			document := model.Asset{
				Title:    popular.Value,
				Value:    popular.Value,
				Created:  popular.Created,
				Modified: popular.Created,
				Type:     defs.AssetTypeProduct,
				Visible:  true,
				Active:   true,
				Status:   defs.AssetStatusCodeApproved,
				Creator:  body.Creator,
				Attribute: model.ProductAttribute{
					Vendor:  pro.Vendor().String(),
					Part:    pro.Part().String(),
					Product: pro.Product().String(),
					Version: "*",
					Update:  "*",
					Popular: true,
				},
			}
			document.Organization = org.TenantID
			document.GenID()
			assetIDs = append(assetIDs, document.ID)
			if _, err := inst.elastic.Enduser().Asset().GetByID(context.Background(), document.ID); err != nil {
				if err.Error() != es.NotFoundError {
					return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
				}
				assets = append(assets, &document)
			}
		}
	}
	// Insert
	if len(assets) > 0 {
		productMapping := map[string][]string{}
		for _, product := range assets {
			if value, ok := productMapping[product.Organization]; ok {
				value = append(value, product.Value)
				productMapping[product.Organization] = value
			} else {
				productMapping[product.Organization] = []string{product.Value}
			}
		}
		for org, products := range productMapping {
			msg := &model.ProductMapping{Organization: org, Assets: products}
			bts, err := json.Marshal(msg)
			if err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
			if err = inst.queue.Publish("", defs.QueueCveMapping, rabbit.Message{
				Body:        bts,
				ContentType: rabbit.MIMEApplicationJSON,
				Mode:        rabbit.Persistent,
			}); err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
		}
		if err = inst.elastic.Enduser().Asset().StoreAll(context.Background(), assets); err != nil {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	// Remove all asset not in list
	queryPopularAsset := map[string]interface{}{
		"bool": map[string]interface{}{
			"filter": []interface{}{
				map[string]interface{}{
					"term": map[string]interface{}{
						"attribute.popular": true,
					},
				},
				map[string]interface{}{
					"term": map[string]interface{}{
						"type": defs.AssetTypeProduct,
					},
				},
			},
		},
	}
	popularAssets, err := inst.elastic.Enduser().Asset().FindAll(context.Background(), queryPopularAsset, []string{})
	if err != nil {
		if err.Error() != es.NotFoundError {
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	for _, popular := range popularAssets {
		if !slice.String(assetIDs).Contains(popular.ID) && popular.Visible {
			if err = inst.elastic.Enduser().Asset().DeleteByID(context.Background(), popular.ID); err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
			}
		}
	}
	//Success
	return rest.JSON(c).Code(rest.StatusOK).Go()
}

func (inst *AssetProductHandler) verifyProducts(c echo.Context) (body model.RequestAssetProducts, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	products := make([]string, 0)
	for _, product := range body.Products {
		products = append(products, strings.ToLower(product))
	}
	body.Products = products
	// Success
	return body, nil
}

func (inst *AssetProductHandler) verifyProductIDs(c echo.Context) (body model.RequestAssetProductIDs, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	ids := make([]string, 0)
	for _, id := range body.IDs {
		ids = append(ids, strings.ToLower(id))
	}
	body.IDs = ids
	// Success
	return body, nil
}

func (inst *AssetProductHandler) verifySearch(c echo.Context) (body model.RequestAssetProductSearch, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
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
	if len(body.Part) > 0 {
		parts := make([]string, 0)
		for _, part := range body.Part {
			part = strings.ToLower(part)
			parts = append(parts, part)
			if _, ok := defs.MappingProductPart[part]; !ok {
				return body, errors.New("invalid value for parameter <part>")
			}
		}
		body.Part = parts
	}
	if body.Active != "" {
		body.Active = strings.ToLower(body.Active)
		if _, ok := defs.MappingAssetActive[body.Active]; !ok {
			return body, errors.New("invalid value for parameter <active>")
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

func (inst *AssetProductHandler) verifyStatistic(c echo.Context) (body model.RequestAssetProductStatistic, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	// Success
	return body, nil
}

func (inst *AssetProductHandler) verifyCreate(c echo.Context) (body model.RequestAssetProductCreate, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	if body.Organization == "" {
		return body, errors.New("invalid value for parameter <organization>")
	}
	products := make([]string, 0)
	for _, product := range body.Products {
		product = strings.ToLower(product)
		_, err := cpe.NewItemFromFormattedString(product)
		if err != nil {
			return body, err
		}
		products = append(products, product)
	}
	body.Products = products
	// Success
	return body, nil
}

func (inst *AssetProductHandler) verifyEdit(c echo.Context) (body model.RequestAssetProductEdit, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	body.Product = strings.ToLower(body.Product)
	_, err = cpe.NewItemFromFormattedString(body.Product)
	if err != nil {
		return body, err
	}
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

func (inst *AssetProductHandler) verifySynchronize(c echo.Context) (body model.RequestAssetProductSynchronize, err error) {
	if err = Validate(c, &body); err != nil {
		return body, err
	}
	if body.Creator == "" {
		body.Creator = defs.DefaultCreator
	}
	// Success
	return body, nil
}

func (inst *AssetProductHandler) collectOrganizations() {
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

/*
Import
Follow: User import => receive analyze data and report_id => send request to create asset by report_id
Note::  Performance: decode file10Mb(~400k record) = 20s
*/
func (inst *AssetProductHandler) Import(c echo.Context) error {
	var (
		err      error
		reportID = uuid.New().String()
		result   = handleImportMsg{ReportID: reportID, FileError: []string{}}
	)
	creator := c.FormValue("creator")
	if creator == "" {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	organization := c.FormValue("org")
	if organization == "" {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}
	files, err := c.MultipartForm()
	if err != nil {
		return rest.JSON(c).Code(rest.StatusBadRequest).Log(err).Go()
	}

	for _, f := range files.File["file"] {
		v, err := inst.handlerSingleFileImport(creator, organization, f)
		if err != nil {
			log.Error(err)
			result.FileError = append(result.FileError, f.Filename)
			continue
		}
		result.Documents = append(result.Documents, v.Documents...)
		result.Duplicate += v.Duplicate
		result.Success += v.Success
		result.Fail = append(result.Fail, v.Fail...)
		result.SuccessDetail = append(result.SuccessDetail, v.SuccessDetail...)
	}

	//statusSet := inst.lru.Set(reportID, result)
	//if !statusSet {
	//	return rest.JSON(c).Code(rest.StatusOK).Log(errors.New("Can not store error row excel ")).Go()
	//}

	//Save result to redis
	ttlCache := clock.Minute * 30
	err = inst.cache.Strings().SetO(reportID, result, ttlCache)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusOK).Log(errors.New("Can not store error row excel ")).Go()
	}
	return rest.JSON(c).Code(rest.StatusOK).Body(map[string]interface{}{
		"duplicate":   result.Duplicate,
		"success":     result.Success,
		"fail":        result.responseFailDetails(),
		"file_error":  result.FileError,
		"report_id":   result.ReportID,
		"total_error": len(result.Fail),
	}).Go()
}

func (inst *AssetProductHandler) DownloadReport(c echo.Context) error {
	requestID := c.Param("id")
	var err error
	requestDetail := handleImportMsg{}
	err = inst.cache.Strings().GetO(requestID, &requestDetail)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusNotFound).Go()
	}
	f, err := excelize.OpenFile(importErrorTemplateFilePath)
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Go()
	}
	//line := 4
	for _, row := range requestDetail.Fail {
		for col, v := range row {
			err := f.SetCellValue(f.GetSheetName(0), col, v)
			if err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Go()
			}
		}
		// line++
	}

	for _, row := range requestDetail.SuccessDetail {
		for col, v := range row {
			err := f.SetCellValue(f.GetSheetName(0), col, v)
			if err != nil {
				return rest.JSON(c).Code(rest.StatusInternalServerError).Go()
			}
		}
		// line++
	}

	// Set active sheet of the workbook.
	f.SetActiveSheet(0)
	buf, err := f.WriteToBuffer()
	if err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Go()
	}
	if buf == nil {
		err = errors.New("Cant not export file ")
		log.Error(err)
		return rest.JSON(c).Code(rest.StatusInternalServerError).Go()
	}
	now := time.Now()
	c.Response().Header().Set(echo.HeaderContentDisposition,
		fmt.Sprintf("attachment;filename=VTI_report_%d:%.2d:%.2d_%.2d:%.2d.xlsx", now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute()))
	http.ServeContent(c.Response(), c.Request(), "filename", time.Now(), bytes.NewReader(buf.Bytes()))
	return nil
}

/*
handlerSingleFileImport
This function handle a file in request import assets
*/
func (inst *AssetProductHandler) handlerSingleFileImport(creator, organization string, f *multipart.FileHeader) (*handleImportMsg, error) {
	fBuff, err := f.Open()
	if err != nil {
		return nil, err
	}
	fData, err := ioutil.ReadAll(fBuff)
	if err != nil {
		return nil, err
	}
	excel, err := xlsxreader.NewReader(fData)
	if err != nil {
		return nil, err
	}

	now, _ := clock.Now(clock.Local)
	nowTimestamp := clock.UnixMilli(now)
	documents := make([]*model.Asset, 0)
	errRecords := make(chan xlsxreader.Row, 1)
	validRecords := make(chan xlsxreader.Row, 1)

	var duplicate, line int64
	errReport := make([]map[string]interface{}, 0)
	validReport := make([]map[string]interface{}, 0)
	mp := make(map[string]int)

	go func() {
		inst.wg.Add(1)
		for row := range errRecords {
			cols := map[string]interface{}{}
			var note string
			mp := map[string]int{}
			for _, v := range row.Cells {
				outCell := fmt.Sprintf("%s%d", v.Column, v.Row)
				cols[outCell] = v.Value
				if v.Column == "G" {
					note += v.Value + ", "
				}
				mp[v.Column] = 1
			}
			hMsg := handleImportMsg{}
			for col, key := range hMsg.mappingCells() {
				if _, ok := mp[col]; !ok && col != "G" {
					note += fmt.Sprintf(`%s%s is required, `, strings.ToUpper(string(key[0])), key[1:])
				}
			}
			note = strings.TrimSuffix(note, ", ")
			cols[fmt.Sprintf("%s%d", "G", row.Index)] = note
			errReport = append(errReport, cols)
		}
		log.Info("Close error chan")
		defer inst.wg.Done()
	}()

	go func() {
		inst.wg.Add(1)
		for row := range validRecords {
			cols := map[string]interface{}{}
			for _, v := range row.Cells {
				outCell := fmt.Sprintf("%s%d", v.Column, v.Row)
				cols[outCell] = v.Value
			}
			validReport = append(validReport, cols)
		}
		log.Info("Close valid chan")
		inst.wg.Done()
	}()

	for row := range excel.ReadRows(excel.Sheets[0]) {
		line = int64(row.Index)
		if row.Index < 4 {
			if err = inst.validateFileImport(row); err != nil {
				return nil, err
			}
			continue
		}
		if len(row.Cells) < 6 {
			errRecords <- row
			continue
		}
		vendor := strings.Join(strings.Fields(strings.TrimSpace(strings.ToLower(row.Cells[1].Value))), "_")
		if vendor == "" {
			row.Cells = append(row.Cells, xlsxreader.Cell{
				Column: "G",
				Row:    row.Index,
				Value:  "Owner is required",
				Type:   "",
			})
			errRecords <- row
			continue
		}
		productType := strings.ToLower(strings.TrimSpace(row.Cells[2].Value))
		if productType == "" {
			row.Cells = append(row.Cells, xlsxreader.Cell{
				Column: "G",
				Row:    row.Index,
				Value:  "Product type is required",
				Type:   "",
			})
			errRecords <- row
			continue
		}

		if _, ok := defs.MappingProductType[productType]; !ok {
			row.Cells = append(row.Cells, xlsxreader.Cell{
				Column: "G",
				Row:    row.Index,
				Value:  "Product type is invalid",
				Type:   "",
			})
			errRecords <- row
			continue
		}
		productType = defs.MappingProductType[productType]

		product := strings.Join(strings.Fields(strings.TrimSpace(strings.ToLower(row.Cells[3].Value))), "_")
		if product == "" {
			row.Cells = append(row.Cells, xlsxreader.Cell{
				Column: "G",
				Row:    row.Index,
				Value:  "Product is required",
				Type:   "",
			})
			errRecords <- row
			continue
		}
		version := strings.Join(strings.Fields(strings.TrimSpace(strings.ToLower(row.Cells[4].Value))), "_")
		if version == "" {
			row.Cells = append(row.Cells, xlsxreader.Cell{
				Column: "G",
				Row:    row.Index,
				Value:  "Version is required",
				Type:   "",
			})
			errRecords <- row
			continue
		}

		update := strings.Join(strings.Fields(strings.TrimSpace(strings.ToLower(row.Cells[5].Value))), "_")
		if update == "" {
			row.Cells = append(row.Cells, xlsxreader.Cell{
				Column: "G",
				Row:    row.Index,
				Value:  "Update is required",
				Type:   "",
			})
			errRecords <- row
			continue
		}
		prod := cpe.NewItem()
		_ = prod.SetVendor(cpe.NewStringAttr(vendor))
		_ = prod.SetPart(defs.MappingCPEProductPart[productType])
		_ = prod.SetProduct(cpe.NewStringAttr(product))
		_ = prod.SetVersion(cpe.NewStringAttr(version))
		_ = prod.SetUpdate(cpe.NewStringAttr(update))
		document := &model.Asset{
			Title:        prod.Formatted(),
			Value:        prod.Formatted(),
			Created:      nowTimestamp,
			Modified:     nowTimestamp,
			Type:         defs.AssetTypeProduct,
			Visible:      true,
			Active:       true,
			Status:       defs.AssetStatusCodeApproved,
			Creator:      creator,
			Organization: organization,
			Attribute: model.M{
				"product_vendor":  vendor,
				"product_part":    productType,
				"product_product": product,
				"product_version": version,
				"product_update":  update,
				"popular":         false,
			},
		}
		document.GenID()
		// remove duplicate
		if stt, ok := mp[document.ID]; ok {
			fmt.Printf("Value: %s -- ID: %s\n", document.Value, document.ID)
			duplicate++
			row.Cells = append(row.Cells, xlsxreader.Cell{
				Column: "G",
				Row:    row.Index,
				Value:  fmt.Sprintf("Asset is duplicate of row %d", stt),
				Type:   "",
			})
			errRecords <- row
			continue
		}
		mp[document.ID] = row.Index
		if _, err := inst.elastic.Enduser().Asset().GetByID(context.Background(), document.ID); err != nil {
			if err.Error() != es.NotFoundError {
				return nil, err
			}
		} else {
			duplicate++
			row.Cells = append(row.Cells, xlsxreader.Cell{
				Column: "G",
				Row:    row.Index,
				Value:  "Asset is exist",
				Type:   "",
			})
			errRecords <- row
			continue
		}
		validRecords <- row
		documents = append(documents, document)
	}
	close(errRecords)
	close(validRecords)
	inst.wg.Wait()
	if len(documents) == 0 && len(errReport) == 0 || line < 4 {
		return nil, errors.New(fmt.Sprintf("file %s is invalid", f.Filename))
	}
	// Success
	return &handleImportMsg{
		Documents:     documents,
		Duplicate:     duplicate,
		Success:       int64(len(documents)),
		SuccessDetail: validReport,
		Fail:          errReport,
	}, nil
}

func (inst *AssetProductHandler) BulkByImportRequestID(c echo.Context) error {
	requestID := c.Param("id")
	var err error
	requestDetail := handleImportMsg{}
	err = inst.cache.Strings().GetO(requestID, &requestDetail)
	if err != nil {
		fmt.Printf("err: %v", err)
		return rest.JSON(c).Code(rest.StatusBadRequest).Go()
	}

	if err := inst.elastic.Enduser().Asset().StoreAll(context.Background(), requestDetail.Documents); err != nil {
		return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
	}

	// send kafka events
	for _, doc := range requestDetail.Documents {
		if err = inst.kafka.SendChangeAsset(nil, doc, defs.TitleActionCreate); err != nil {
			inst.logger.Errorf("failed to send Kafka asset product event, reason: %v", err)
			return rest.JSON(c).Code(rest.StatusInternalServerError).Log(err).Go()
		}
	}
	return rest.JSON(c).Code(rest.StatusOK).Go()
}

func (inst *AssetProductHandler) validateFileImport(row xlsxreader.Row) error {
	var err = errors.New("invalid file import")
	if row.Index != inst.importTemplate.Index {
		return nil
	}

	if len(row.Cells) < len(inst.importTemplate.Cells) {
		return err
	}

	for id, collum := range inst.importTemplate.Cells {
		if row.Cells[id].Value != collum.Value {
			return err
		}
	}
	if len(row.Cells) == 7 {
		if strings.ToLower(row.Cells[6].Value) != "note" {
			return err
		}
	}
	if len(row.Cells) > 7 {
		return err
	}
	return nil
}
