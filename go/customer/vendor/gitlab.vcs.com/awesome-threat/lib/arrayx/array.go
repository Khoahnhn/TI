package arrayx

func Index[T comparable](arr []T, value T) int {
	for i, item := range arr {
		if item == value {
			return i
		}
	}
	return -1
}

func Contain[T comparable](arr []T, value T) bool {
	// Success
	return Index(arr, value) > -1
}

func Unique[T comparable](arr []T) []T {
	mapArr := make(map[T]bool)
	for _, item := range arr {
		mapArr[item] = true
	}
	newArr := make([]T, 0)
	for key, _ := range mapArr {
		newArr = append(newArr, key)
	}
	// Success
	return newArr
}

func RemoveItem[T comparable](arr []T, value T) []T {
	newArr := make([]T, 0)
	for _, item := range arr {
		if item == value {
			continue
		}
		newArr = append(newArr, item)
	}
	// Success
	return newArr
}

func RemoveItems[T comparable](arr []T, values []T) []T {
	newArr := make([]T, 0)
	for _, item := range arr {
		if Contain(values, item) {
			continue
		}
		newArr = append(newArr, item)
	}
	// Success
	return newArr
}

func Reverse[T any](arr []T) []T {
	reversed := make([]T, len(arr))
	for i, j := 0, len(arr)-1; i < len(arr); i, j = i+1, j-1 {
		reversed[i] = arr[j]
	}
	// Success
	return reversed
}
