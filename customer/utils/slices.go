package utils

import "reflect"

func SliceContains[V any](s []V, e V) bool {
	for _, o := range s {
		if reflect.DeepEqual(o, e) {
			return true
		}
	}
	return false
}

func MapKeysToSlice[V comparable, T any](mp map[V]T) []V {
	res := make([]V, 0, len(mp))
	for k := range mp {
		res = append(res, k)
	}
	return res
}
