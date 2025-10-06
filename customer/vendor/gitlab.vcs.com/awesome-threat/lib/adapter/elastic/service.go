package elastic

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"

	es "github.com/olivere/elastic/v7"
)

type service struct {
	con *ES
}

func NewService(conf Config) Service {
	opts := make([]es.ClientOptionFunc, 0)
	addresses := strings.Split(conf.Address, ",")
	opts = append(opts, es.SetURL(addresses...), es.SetSniff(false))
	if conf.Auth.Enable {
		opts = append(opts, es.SetBasicAuth(conf.Auth.Username, conf.Auth.Password))
	}
	client, err := es.NewClient(opts...)
	if err != nil {
		panic(err)
	}
	// Success
	return &service{con: &ES{model: client}}
}

func (inst *service) Get(database, _, id string, result Document) error {
	res, err := inst.con.Get(database, id)
	if err != nil {
		if es.IsNotFound(err) {
			return errors.New(NotFoundError)
		}
		return err
	}
	err = json.Unmarshal(res.Source, result)
	if err != nil {
		return err
	}
	result.SetEID(res.Id)
	// Success
	return nil
}

func (inst *service) Exists(database, _, id string) (bool, error) {
	// Success
	return inst.con.Exists(database, id)
}

func (inst *service) Count(database, _ string, query Query) (int64, error) {
	// Success
	return inst.con.Count(database, query)
}

func (inst *service) FindOne(database, _ string, query Query, sorts []string, result interface{}) error {
	if reflect.TypeOf(result).Kind() != reflect.Ptr {
		return errors.New(ResultIsNotAPointer)
	}
	res, err := inst.con.SearchOffset(database, query, sorts, 0, 1)
	if err != nil || res.Hits == nil {
		return err
	}
	if res.Hits.TotalHits.Value == 0 {
		return errors.New(NotFoundError)
	}
	err = json.Unmarshal(res.Hits.Hits[0].Source, result)
	if err != nil {
		return err
	}
	temp, ok := result.(Document)
	if !ok {
		return errors.New(ResultIsNotImplementation)
	}
	temp.SetEID(res.Hits.Hits[0].Id)
	// Success
	return nil
}

func (inst *service) FindPaging(database, _ string, query Query, sorts []string, page, size int, results interface{}) (int64, error) {
	res, err := inst.con.SearchPaging(database, query, sorts, page, size)
	if err != nil || res.Hits == nil {
		return 0, err
	}
	if res.Hits.TotalHits.Value == 0 {
		return 0, errors.New(NotFoundError)
	}
	resultType := reflect.TypeOf(results)
	resultValue := reflect.ValueOf(results)
	resultElemType := resultType.Elem().Elem()
	if resultType.Kind() != reflect.Ptr {
		return 0, errors.New(ResultIsNotAPointer)
	}
	count := res.Hits.TotalHits.Value
	for _, hit := range res.Hits.Hits {
		itemValue := reflect.New(resultElemType)
		if err = json.Unmarshal(hit.Source, itemValue.Interface()); err != nil {
			return count, err
		}
		if value, ok := itemValue.Elem().Interface().(Document); !ok {
			return 0, errors.New(ResultIsNotImplementation)
		} else {
			value.SetEID(hit.Id)
		}
		resultValue.Elem().Set(reflect.Append(resultValue.Elem(), itemValue.Elem()))
	}
	// Success
	return count, nil
}

func (inst *service) FindOffset(database, _ string, query Query, sorts []string, offset, size int, results interface{}) (int64, error) {
	res, err := inst.con.SearchOffset(database, query, sorts, offset, size)
	if err != nil || res.Hits == nil {
		return 0, err
	}
	if res.Hits.TotalHits.Value == 0 {
		return 0, errors.New(NotFoundError)
	}
	resultType := reflect.TypeOf(results)
	resultValue := reflect.ValueOf(results)
	resultElemType := resultType.Elem().Elem()
	if resultType.Kind() != reflect.Ptr {
		return 0, errors.New(ResultIsNotAPointer)
	}
	count := res.Hits.TotalHits.Value
	for _, hit := range res.Hits.Hits {
		itemValue := reflect.New(resultElemType)
		if err = json.Unmarshal(hit.Source, itemValue.Interface()); err != nil {
			return count, err
		}
		if value, ok := itemValue.Elem().Interface().(Document); !ok {
			return 0, errors.New(ResultIsNotImplementation)
		} else {
			value.SetEID(hit.Id)
		}
		resultValue.Elem().Set(reflect.Append(resultValue.Elem(), itemValue.Elem()))
	}
	// Success
	return count, nil
}

func (inst *service) FindScroll(database, _ string, query Query, sorts []string, size int, scrollID, keepAlive string, results interface{}) (string, int64, error) {
	res, err := inst.con.SearchScroll(database, query, sorts, size, scrollID, keepAlive)
	if err != nil || res.Hits == nil {
		return "", 0, err
	}
	if res.Hits.TotalHits.Value == 0 {
		return "", 0, errors.New(NotFoundError)
	}
	resultType := reflect.TypeOf(results)
	resultValue := reflect.ValueOf(results)
	resultElemType := resultType.Elem().Elem()
	if resultType.Kind() != reflect.Ptr {
		return "", 0, errors.New(ResultIsNotAPointer)
	}
	count := res.Hits.TotalHits.Value
	for _, hit := range res.Hits.Hits {
		itemValue := reflect.New(resultElemType)
		if err = json.Unmarshal(hit.Source, itemValue.Interface()); err != nil {
			return "", 0, err
		}
		if value, ok := itemValue.Elem().Interface().(Document); !ok {
			return "", 0, errors.New(ResultIsNotImplementation)
		} else {
			value.SetEID(hit.Id)
		}
		resultValue.Elem().Set(reflect.Append(resultValue.Elem(), itemValue.Elem()))
	}
	// Success
	return res.ScrollId, count, nil
}

func (inst *service) FindCollapse(database, _ string, query Query, sorts []string, field string, offset, size int, results interface{}) (int64, error) {
	res, err := inst.con.SearchCollapse(database, query, sorts, field, offset, size)
	if err != nil || res.Hits == nil {
		return 0, err
	}
	if res.Hits.TotalHits.Value == 0 {
		return 0, errors.New(NotFoundError)
	}
	resultType := reflect.TypeOf(results)
	resultValue := reflect.ValueOf(results)
	resultElemType := resultType.Elem().Elem()
	if resultType.Kind() != reflect.Ptr {
		return 0, errors.New(ResultIsNotAPointer)
	}
	count := res.Hits.TotalHits.Value
	for _, hit := range res.Hits.Hits {
		itemValue := reflect.New(resultElemType)
		if err = json.Unmarshal(hit.Source, itemValue.Interface()); err != nil {
			return count, err
		}
		if value, ok := itemValue.Elem().Interface().(Document); !ok {
			return 0, errors.New(ResultIsNotImplementation)
		} else {
			value.SetEID(hit.Id)
		}
		resultValue.Elem().Set(reflect.Append(resultValue.Elem(), itemValue.Elem()))
	}
	// Success
	return count, nil
}

func (inst *service) InsertOne(database, _ string, doc Document) error {
	_, err := inst.con.Index(database, doc)
	if err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *service) InsertMany(database, _ string, docs []Document) error {
	bulk := inst.con.Bulk()
	for idx := range docs {
		bulk.Index(database, docs[idx].GetID(), docs[idx])
	}
	err := bulk.Do()
	if err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *service) UpdateByID(database, _, id string, update interface{}, upsert bool) error {
	_, err := inst.con.Update(database, id, update, upsert)
	if err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *service) UpdateMany(database, _ string, updates []UpdateDocument) error {
	bulk := inst.con.Bulk()
	upsert := false
	for idx := range updates {
		bulk.Update(database, updates[idx].ID, updates[idx].Update, upsert)
	}
	err := bulk.Do()
	if err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *service) DeleteByID(database, _, id string) error {
	_, err := inst.con.DeleteByID(database, id)
	if err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *service) DeleteMany(database, _ string, query Query) error {
	_, err := inst.con.DeleteByQuery(database, query)
	if err != nil {
		return err
	}
	// Success
	return nil
}

func (inst *service) AggregationCount(database, _ string, query Query, fields []string) (map[string][]ResultAggregationCount, error) {
	aggs := map[string]es.Aggregation{}
	for _, field := range fields {
		term := es.NewTermsAggregation().Field(field)
		aggs[field] = term
	}
	res, err := inst.con.Aggregation(database, query, aggs)
	if err != nil {
		return nil, err
	}
	results := map[string][]ResultAggregationCount{}
	for _, field := range fields {
		bucket, ok := res.Terms(field)
		if !ok {
			continue
		}
		result := make([]ResultAggregationCount, 0)
		for _, b := range bucket.Buckets {
			result = append(result, ResultAggregationCount{
				Value: b.Key,
				Count: b.DocCount,
			})
		}
		results[field] = result
	}
	// Success
	return results, nil
}

func (inst *service) AggregationCountWithSize(database, _ string, query Query, fields map[string]int) (map[string][]ResultAggregationCount, error) {
	aggs := map[string]es.Aggregation{}
	for field, size := range fields {
		term := es.NewTermsAggregation().Field(field).Size(size)
		aggs[field] = term
	}
	res, err := inst.con.Aggregation(database, query, aggs)
	if err != nil {
		return nil, err
	}
	results := map[string][]ResultAggregationCount{}
	for field, _ := range fields {
		bucket, ok := res.Terms(field)
		if !ok {
			continue
		}
		result := make([]ResultAggregationCount, 0)
		for _, b := range bucket.Buckets {
			result = append(result, ResultAggregationCount{
				Value: b.Key,
				Count: b.DocCount,
			})
		}
		results[field] = result
	}
	// Success
	return results, nil
}

func (inst *service) Aggregation(database, _ string, query Query, aggregations map[string]es.Aggregation) (*es.Aggregations, error) {
	// Success
	return inst.con.Aggregation(database, query, aggregations)
}
