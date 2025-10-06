package utils

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

func GeneratePassword() string {
	// Generate random password with mixed characters (8-12 length)
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
	const passwordLength = 10 // magic number?

	password := make([]byte, passwordLength)
	for i := range password {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		password[i] = charset[n.Int64()]
	}

	return string(password)
}

func GeneratePasswordHash(password string, method string, saltLength int) string {
	if method == "" {
		method = "pbkdf2:sha256"
	}
	if saltLength <= 0 {
		saltLength = 8
	}

	// Generate salt (except for plain method)
	var salt string
	if method != "plain" {
		salt = genSalt(saltLength)
	}

	// Hash the password
	hashedPassword, actualMethod := hashInternal(method, salt, password)

	// Return in format: method$salt$hash
	return fmt.Sprintf("%s$%s$%s", actualMethod, salt, hashedPassword)
}

func genSalt(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	salt := make([]byte, length)

	for i := range salt {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		salt[i] = charset[n.Int64()]
	}

	return string(salt)
}

func hashInternal(method, salt, password string) (string, string) {
	if method == "plain" {
		return password, "plain"
	}

	// Check if it's PBKDF2 method
	if strings.HasPrefix(method, "pbkdf2:") {
		return hashPBKDF2(method, salt, password)
	}

	// For other hash methods (sha256, sha512, etc.), use HMAC
	return hashHMAC(method, salt, password), method
}

func hashPBKDF2(method, salt, password string) (string, string) {
	parts := strings.Split(method, ":")
	if len(parts) < 2 {
		return "", method
	}

	hashMethod := parts[1]
	iterations := 260000 // Default Werkzeug PBKDF2 iterations

	// Parse custom iterations if provided
	if len(parts) >= 3 {
		if customIter, err := strconv.Atoi(parts[2]); err == nil {
			iterations = customIter
		}
	}

	// Select hash function
	var hashFunc func() hash.Hash
	var keyLen int

	switch hashMethod {
	case "sha256":
		hashFunc = sha256.New
		keyLen = 32
	case "sha512":
		hashFunc = sha512.New
		keyLen = 64
	case "sha1":
		// Note: SHA1 is deprecated but kept for compatibility
		hashFunc = sha256.New // Use SHA256 as fallback
		keyLen = 32
	default:
		hashFunc = sha256.New
		keyLen = 32
	}

	// Generate PBKDF2 hash
	dk := pbkdf2.Key([]byte(password), []byte(salt), iterations, keyLen, hashFunc)

	return hex.EncodeToString(dk), method
}

func hashHMAC(method, salt, password string) string {
	var hashFunc func() hash.Hash

	switch method {
	case "sha256":
		hashFunc = sha256.New
	case "sha512":
		hashFunc = sha512.New
	default:
		hashFunc = sha256.New
	}

	// Create HMAC with salt as key
	mac := hmac.New(hashFunc, []byte(salt))
	mac.Write([]byte(password))

	return hex.EncodeToString(mac.Sum(nil))
}