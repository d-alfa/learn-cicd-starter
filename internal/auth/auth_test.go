package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Test case 1: Valid Authorization header
	headers := make(http.Header)
	headers.Set("Authorization", "ApiKey my-api-key")
	key, err := GetAPIKey(headers)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if key != "my-api-key" {
		t.Errorf("Expected API key %s, but got %s", "my-api-key", key)
	}

	// Test case 2: Missing Authorization header
	headers = make(http.Header)
	key, err = GetAPIKey(headers)
	if err == nil {
		t.Error("Expected error, but got nil")
	}
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("Expected error %v, but got %v", ErrNoAuthHeaderIncluded, err)
	}

	// Test case 3: Malformed Authorization header
	headers = make(http.Header)
	headers.Set("Authorization", "Bearer token") // Incorrect prefix
	key, err = GetAPIKey(headers)
	expectedErr := errors.New("malformed authorization header")
	if err == nil {
		t.Error("Expected error, but got nil")
	}
	if err.Error() != expectedErr.Error() {
		t.Errorf("Expected error %v, but got %v", expectedErr, err)
	}
}

