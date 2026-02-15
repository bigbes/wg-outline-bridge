package miniapp

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

func buildInitData(botToken string, userID int64, extra map[string]string) string {
	params := url.Values{}
	params.Set("auth_date", fmt.Sprintf("%d", time.Now().Unix()))
	params.Set("user", fmt.Sprintf(`{"id":%d,"first_name":"Test"}`, userID))
	for k, v := range extra {
		params.Set(k, v)
	}

	// Build data_check_string.
	var pairs []string
	for key := range params {
		pairs = append(pairs, key+"="+params.Get(key))
	}
	sort.Strings(pairs)
	dataCheckString := strings.Join(pairs, "\n")

	// Compute hash.
	secretKey := hmac.New(sha256.New, []byte("WebAppData"))
	secretKey.Write([]byte(botToken))
	secret := secretKey.Sum(nil)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(dataCheckString))
	hash := hex.EncodeToString(mac.Sum(nil))

	params.Set("hash", hash)
	return params.Encode()
}

func TestValidateInitData(t *testing.T) {
	token := "123456:ABC-DEF-test-token"

	initData := buildInitData(token, 42, nil)
	userID, err := ValidateInitData(initData, token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if userID != 42 {
		t.Fatalf("expected user ID 42, got %d", userID)
	}
}

func TestValidateInitData_InvalidHash(t *testing.T) {
	token := "123456:ABC-DEF-test-token"
	initData := buildInitData(token, 42, nil)

	_, err := ValidateInitData(initData, "wrong-token")
	if err == nil {
		t.Fatal("expected error for wrong token")
	}
}

func TestValidateInitData_Expired(t *testing.T) {
	token := "123456:ABC-DEF-test-token"
	initData := buildInitData(token, 42, map[string]string{
		"auth_date": fmt.Sprintf("%d", time.Now().Add(-25*time.Hour).Unix()),
	})
	// Re-sign with correct auth_date.
	params, _ := url.ParseQuery(initData)
	params.Set("auth_date", fmt.Sprintf("%d", time.Now().Add(-25*time.Hour).Unix()))
	params.Del("hash")

	var pairs []string
	for key := range params {
		pairs = append(pairs, key+"="+params.Get(key))
	}
	sort.Strings(pairs)
	dataCheckString := strings.Join(pairs, "\n")

	secretKey := hmac.New(sha256.New, []byte("WebAppData"))
	secretKey.Write([]byte(token))
	secret := secretKey.Sum(nil)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(dataCheckString))
	params.Set("hash", hex.EncodeToString(mac.Sum(nil)))

	_, err := ValidateInitData(params.Encode(), token)
	if err == nil {
		t.Fatal("expected error for expired init data")
	}
}
