package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Test case 1: Valid Authorization header
	headers1 := make(http.Header)
	headers1.Set("Authorization", "ApiKey my-api-key")
	key, err := GetAPIKey(headers1)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if key != "my-api-key" {
		t.Fatalf("Expected API key %s, but got %s", "my-api-key", key)
	}

	// Test case 2: Missing Authorization header
	headers2 := make(http.Header)
	_, err = GetAPIKey(headers2)
	if err == nil || err != ErrNoAuthHeaderIncluded {
		t.Fatalf("Expected error %v, but got %v", ErrNoAuthHeaderIncluded, err)
	}

	// Test case 3: Malformed Authorization header
	headers3 := make(http.Header)
	headers3.Set("Authorization", "Bearer token") // Incorrect prefix
	_, err = GetAPIKey(headers3)
	expectedErr := errors.New("malformed authorization header")
	if err == nil || err.Error() != expectedErr.Error() {
		t.Fatalf("Expected error %v, but got %v", expectedErr, err)
	}
}
