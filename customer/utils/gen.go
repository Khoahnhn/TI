package utils

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

var resourceTypeDict = map[string]bool{
	"api_key": true,
	"intel":   true,
}

// Lấy prefix dựa trên resource type
func getPrefix(resourceType string) string {
	prefixMap := map[string]string{
		"api_key": "ak_",
		"intel":   "int_",
	}

	if prefix, exists := prefixMap[resourceType]; exists {
		return prefix
	}
	return ""
}

// Generate ID by microsecond
func GenID(resourceType string) (string, error) {
	// Kiểm tra resource type có được hỗ trợ không
	if !resourceTypeDict[resourceType] {
		return "", errors.New("object type id is not supported")
	}

	prefix := getPrefix(resourceType)
	timestamp := time.Now().Unix()

	// Trường hợp đặc biệt cho intel
	if resourceType == "intel" {
		return "", nil // Trả về empty string như code Python gốc
	}

	// Tạo 10 bytes random
	randomBytes := make([]byte, 10)
	rand.Read(randomBytes)

	// Chuyển random bytes thành hex string
	randomHex := hex.EncodeToString(randomBytes)

	// Tạo object_id
	objectID := fmt.Sprintf("%s%s%s", prefix, strconv.FormatInt(timestamp, 10), randomHex)

	// Xử lý khác nhau cho api_key
	if resourceType == "api_key" {
		// Tạo SHA1 hash và lấy 25 ký tự đầu
		h := sha1.New()
		h.Write([]byte(objectID))
		hashBytes := h.Sum(nil)
		hashHex := hex.EncodeToString(hashBytes)

		// Lấy 25 ký tự đầu (tương đương [0:25] trong Python)
		if len(hashHex) >= 25 {
			return hashHex[:25], nil
		}
		return hashHex, nil
	}

	return objectID, nil
}

var ResourceTypeDict = map[string]string{
	"confirm_email": "ce",
	"api_key":       "ak",
	"user":          "us",
	"group":         "gr",
	"role":          "rl",
	// thêm các loại khác nếu cần
}

func GetPrefix(resourceType string) (string, error) {
	if prefix, ok := ResourceTypeDict[resourceType]; ok {
		return prefix, nil
	}
	return "", fmt.Errorf("object type id is not supported: %s", resourceType)
}

func GenConfirmMail(resourceType string) (string, error) {
	prefix, err := GetPrefix(resourceType)
	if err != nil {
		return "", err
	}

	timestamp := time.Now().Unix()

	// random 10 bytes
	randomBytes := make([]byte, 10)
	rand.Read(randomBytes)
	randomHex := hex.EncodeToString(randomBytes)

	// build object_id
	objectID := fmt.Sprintf("%s%d%s", prefix, timestamp, randomHex)

	if resourceType == "api_key" {
		sha := sha1.Sum([]byte(objectID))
		return hex.EncodeToString(sha[:])[:25], nil
	}

	return objectID, nil
}
