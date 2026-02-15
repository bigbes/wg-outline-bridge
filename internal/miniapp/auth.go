package miniapp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const maxAuthAge = 24 * time.Hour

// ValidateInitData validates Telegram WebApp init data using HMAC-SHA256.
// Returns the user ID on success.
func ValidateInitData(initData, botToken string) (int64, error) {
	params, err := url.ParseQuery(initData)
	if err != nil {
		return 0, fmt.Errorf("parsing init data: %w", err)
	}

	hash := params.Get("hash")
	if hash == "" {
		return 0, fmt.Errorf("missing hash")
	}

	// Build data_check_string: sorted key=value pairs excluding "hash".
	var pairs []string
	for key := range params {
		if key == "hash" {
			continue
		}
		pairs = append(pairs, key+"="+params.Get(key))
	}
	sort.Strings(pairs)
	dataCheckString := strings.Join(pairs, "\n")

	// secret = HMAC-SHA256("WebAppData", botToken)
	secretKey := hmac.New(sha256.New, []byte("WebAppData"))
	secretKey.Write([]byte(botToken))
	secret := secretKey.Sum(nil)

	// expected = HMAC-SHA256(data_check_string, secret)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(dataCheckString))
	expected := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(hash), []byte(expected)) {
		return 0, fmt.Errorf("invalid hash")
	}

	// Enforce auth_date freshness.
	authDateStr := params.Get("auth_date")
	if authDateStr != "" {
		authDate, err := strconv.ParseInt(authDateStr, 10, 64)
		if err == nil {
			if time.Since(time.Unix(authDate, 0)) > maxAuthAge {
				return 0, fmt.Errorf("init data expired")
			}
		}
	}

	// Extract user ID from the "user" JSON field.
	userJSON := params.Get("user")
	if userJSON == "" {
		return 0, fmt.Errorf("missing user field")
	}

	userID, err := extractUserID(userJSON)
	if err != nil {
		return 0, fmt.Errorf("extracting user id: %w", err)
	}

	return userID, nil
}

// extractUserID extracts "id" from a JSON string like {"id":123,...}
// without importing encoding/json to keep it lightweight.
func extractUserID(userJSON string) (int64, error) {
	// Simple extraction: find "id": followed by a number.
	idx := strings.Index(userJSON, `"id"`)
	if idx < 0 {
		return 0, fmt.Errorf("no id field in user JSON")
	}
	rest := userJSON[idx+4:]
	// Skip whitespace and colon.
	rest = strings.TrimLeft(rest, " \t\n\r:")
	// Read digits.
	var numStr string
	for _, c := range rest {
		if c >= '0' && c <= '9' {
			numStr += string(c)
		} else {
			break
		}
	}
	if numStr == "" {
		return 0, fmt.Errorf("no numeric id value")
	}
	return strconv.ParseInt(numStr, 10, 64)
}
