package ratelimit_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/picatz/httpz/pkg/ratelimit"
)

// TestHandler tests the Handler type.
func TestHandler(t *testing.T) {
	t.Run("1/second", func(t *testing.T) {
		// Create a new limiter that allows a single request per second.
		limiter := rate.NewLimiter(rate.Every(1*time.Second), 1)

		// Create a new handler with the limiter.
		handler := ratelimit.Handler{
			Limiter:       limiter,
			SetRetryAfter: true,
		}

		// Create a new request.
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		// Create a new response recorder.
		rec := httptest.NewRecorder()

		// Serve the request.
		handler.ServeHTTP(rec, req)

		// Check the response status code.
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status code %d, got %d", http.StatusOK, rec.Code)
		}

		// Create a new request.
		req = httptest.NewRequest(http.MethodGet, "/", nil)

		// Create a new response recorder.
		rec = httptest.NewRecorder()

		// Serve the request.
		handler.ServeHTTP(rec, req)

		// Check the response status code.
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected status code %d, got %d", http.StatusTooManyRequests, rec.Code)
		}

		// Check the Retry-After header.
		if retryAfter := rec.Header().Get("Retry-After"); retryAfter != "1s" {
			t.Fatalf("expected Retry-After header to be %q, got %q", "1s", retryAfter)
		}

		// Wait just over a second to allow the next request.
		time.Sleep(2 * time.Second)

		// Create a new request.
		req = httptest.NewRequest(http.MethodGet, "/", nil)

		// Create a new response recorder.
		rec = httptest.NewRecorder()

		// Serve the request.
		handler.ServeHTTP(rec, req)

		// Check the response status code.
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status code %d, got %d", http.StatusOK, rec.Code)
		}

		// Create a new request.
		req = httptest.NewRequest(http.MethodGet, "/", nil)

		// Create a new response recorder.
		rec = httptest.NewRecorder()

		// Serve the request.
		handler.ServeHTTP(rec, req)

		// Check the response status code.
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected status code %d, got %d", http.StatusTooManyRequests, rec.Code)
		}
	})

	t.Run("no limit", func(t *testing.T) {
		// Create a new handler without a limiter.
		handler := ratelimit.Handler{
			Limiter: nil,
		}

		// Create a new request.
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		// Create a new response recorder.
		rec := httptest.NewRecorder()

		// Serve the request.
		handler.ServeHTTP(rec, req)

		// Check the response status code.
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status code %d, got %d", http.StatusOK, rec.Code)
		}

		// Create a new request.
		req = httptest.NewRequest(http.MethodGet, "/", nil)

		// Create a new response recorder.
		rec = httptest.NewRecorder()

		// Serve the request.
		handler.ServeHTTP(rec, req)

		// Check the response status code.
		if rec.Code != http.StatusOK {
			t.Fatalf("expected status code %d, got %d", http.StatusOK, rec.Code)
		}
	})
}
