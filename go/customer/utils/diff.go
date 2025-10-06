package utils

import (
	"encoding/json"
	"reflect"
)

type DiffField struct {
	Before any
	After  any
}

func GetChangedFieldsJson(old, new []byte, keys []string) (map[string]DiffField, error) {
	oldMap := map[string]any{}
	newMap := map[string]any{}
	diff := make(map[string]DiffField)
	if err := json.Unmarshal(old, &oldMap); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(new, &newMap); err != nil {
		return nil, err
	}

	for _, k := range keys {
		oldVal, oldOk := oldMap[k]
		newVal, newOk := newMap[k]
		if oldOk != newOk {
			diff[k] = DiffField{
				Before: oldVal,
				After:  newVal,
			}
			continue
		}
		if oldOk && !reflect.DeepEqual(oldVal, newVal) {
			diff[k] = DiffField{
				Before: oldVal,
				After:  newVal,
			}
		}
	}

	return diff, nil
}
