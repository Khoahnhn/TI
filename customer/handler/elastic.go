package handler

import (
	"context"
	"fmt"
	"os"
	"time"

	es7 "github.com/elastic/go-elasticsearch/v7"
	"github.com/elastic/go-elasticsearch/v7/estransport"

	"gitlab.viettelcyber.com/ti-micro/ws-customer/model"
)

func newElastic(conf *model.Config) (*es7.Client, error) {
	scheme := conf.Adapter.Elastic.Enduser.Scheme
	if scheme == "" {
		scheme = "http"
	}
	addressUrl := fmt.Sprintf("%s://%s", scheme, conf.Adapter.Elastic.Enduser.Address)
	esConfig := es7.Config{
		Addresses: []string{addressUrl},
		Logger:    &estransport.ColorLogger{Output: os.Stdout},
	}
	if conf.Adapter.Elastic.Enduser.Auth.Enable {
		esConfig.Username = conf.Adapter.Elastic.Enduser.Auth.Username
		esConfig.Password = conf.Adapter.Elastic.Enduser.Auth.Password
	}
	client, err := es7.NewClient(esConfig)
	if err != nil {
		return nil, err
	}

	_, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.Ping()
	if err != nil {
		return nil, err
	}
	//err = mappingAssetIndex(conf, client)
	//if err != nil {
	//	log.Println("mappingAssetIndex-error", err)
	//} else {
	//	log.Println("mappingAssetIndex-success")
	//}

	return client, nil
}

//func mappingAssetIndex(conf *model.Config, client *es7.Client) error {
//	// Mapping tags if not exist
//	revertIndex := conf.Adapter.Elastic.Index.TIAsset
//	query := `{"query": {"exists": {"field": "tags"}}}`
//	doc, err := client.Search(client.Search.WithBody(strings.NewReader(query)), client.Search.WithIndex(revertIndex))
//	if err != nil {
//		return err
//	}
//	defer doc.Body.Close()
//	var res model.IndexResult
//	if err = json.NewDecoder(doc.Body).Decode(&res); err != nil {
//		return err
//	}
//
//	if res.Hits.Total.Value == 0 {
//		mapping := `
//		{
//			"properties" : {
//				"tags" : {
//					"type" : "keyword"
//				}
//			}
//		}
//		`
//		mappingReq := &esapi.IndicesPutMappingRequest{
//			Index: []string{revertIndex},
//			Body:  strings.NewReader(mapping),
//		}
//		resp, err := mappingReq.Do(context.Background(), client)
//		if err != nil {
//			return err
//		}
//		defer resp.Body.Close()
//	}
//	// Sync all asset mapping
//	if conf.App.SyncAssetMappingIndex {
//		mapping := `
//		{
//			"mappings" : {
//				"properties" : {
//					"active" : {
//						"type" : "boolean"
//					},
//					"aliases_type" : {
//						"type" : "keyword"
//					},
//					"approved_at" : {
//						"type" : "long"
//					},
//					"attribute" : {
//						"properties" : {
//							"bin" : {
//								"type" : "keyword"
//							},
//							"brand" : {
//								"type" : "boolean"
//							},
//							"domain" : {
//								"type" : "keyword"
//							},
//							"ipaddress" : {
//								"type" : "keyword"
//							},
//							"language" : {
//								"type" : "keyword"
//							},
//							"mask" : {
//								"type" : "keyword"
//							},
//							"match" : {
//								"type" : "keyword"
//							},
//							"name" : {
//								"type" : "keyword"
//							},
//							"network" : {
//								"type" : "keyword"
//							},
//							"popular" : {
//								"type" : "boolean"
//							},
//							"product_part" : {
//								"type" : "keyword"
//							},
//							"product_product" : {
//								"type" : "keyword"
//							},
//							"product_update" : {
//								"type" : "keyword"
//							},
//							"product_vendor" : {
//								"type" : "keyword"
//							},
//							"product_version" : {
//								"type" : "keyword"
//							},
//							"regex" : {
//								"type" : "keyword"
//							},
//							"root" : {
//								"type" : "keyword"
//							},
//							"synonym" : {
//								"type" : "keyword"
//							},
//							"tld" : {
//								"type" : "keyword"
//							}
//						}
//					},
//					"create_time" : {
//						"type" : "date"
//					},
//					"created" : {
//						"type" : "date"
//					},
//					"creator" : {
//						"type" : "keyword"
//					},
//					"history" : {
//						"properties" : {
//							"action" : {
//								"type" : "keyword"
//							},
//							"actor" : {
//								"type" : "keyword"
//							},
//							"note" : {
//								"type" : "text"
//							},
//							"time" : {
//								"type" : "date"
//							}
//						}
//					},
//					"id" : {
//						"type" : "keyword"
//					},
//					"modified" : {
//						"type" : "date"
//					},
//					"modified_time" : {
//						"type" : "date"
//					},
//					"name" : {
//						"type" : "keyword"
//					},
//					"organization" : {
//						"type" : "keyword"
//					},
//					"reason" : {
//						"type" : "text",
//						"fields" : {
//							"keyword" : {
//								"type" : "keyword",
//								"ignore_above" : 256
//							}
//						}
//					},
//					"sla" : {
//						"type" : "long"
//					},
//					"status" : {
//						"type" : "integer"
//					},
//					"storage" : {
//						"type" : "boolean"
//					},
//					"tags" : {
//						"type" : "keyword"
//					},
//					"title" : {
//						"type" : "text"
//					},
//					"type" : {
//						"type" : "keyword"
//					},
//					"value" : {
//						"type" : "keyword"
//					},
//					"visible" : {
//						"type" : "boolean"
//					}
//				}
//			}
//		}
//		`
//		tmpIndex := "tmp-ti-asset"
//		err := deleteIndexSource(tmpIndex, client)
//		if err != nil {
//			return err
//		}
//		err = reindexSource(revertIndex, tmpIndex, client)
//		if err != nil {
//			return err
//		}
//		// Xoa old index
//		err = deleteIndexSource(revertIndex, client)
//		if err != nil {
//			return err
//		}
//
//		// Tao lai index voi mapping moi
//		resp, err := client.Indices.Create(revertIndex, client.Indices.Create.WithBody(strings.NewReader(mapping)))
//		if err != nil {
//			return err
//		}
//		defer resp.Body.Close()
//
//		err = reindexSource(tmpIndex, revertIndex, client)
//		if err != nil {
//			return err
//		}
//	}
//
//	return nil
//}

//func reindexSource(sourceIndex string, destIndex string, client *es7.Client) error {
//	reIndex := fmt.Sprintf(`
//		{
//			"source": {
//				"index": "%s"
//			},
//			"dest": {
//				"index": "%s"
//			}
//		}
//	`, sourceIndex, destIndex)
//	req := &esapi.ReindexRequest{
//		Body: strings.NewReader(reIndex),
//	}
//	resp, err := req.Do(context.Background(), client)
//	if err != nil {
//		return err
//	}
//	defer resp.Body.Close()
//	return nil
//}
//
//func deleteIndexSource(index string, client *es7.Client) error {
//	resp, err := client.Indices.Delete([]string{index})
//	if err != nil {
//		return err
//	}
//	defer resp.Body.Close()
//	return nil
//
//}
