package cookies_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/picatz/httpz/pkg/cookies"
)

func TestCookieRequest(t *testing.T) {
	// Setup a cookie.
	cookie := &cookies.Cookie{
		Name:  "test",
		Value: "Hello",
	}

	// Setup a request.
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	// Set the cookie.
	cookie.SetRequest(r)

	// Get the cookie.
	cookie, err := cookies.Get(r, "test", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure the cookie value is correct.
	if cookie.Value != "Hello" {
		t.Fatalf("expected cookie value to be %q, got %q", "Hello", cookie.Value)
	}
}
