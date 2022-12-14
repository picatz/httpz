package ratelimit

import (
	"net/http"
	"time"

	"golang.org/x/time/rate"
)

// Handler is a net/http middleware that rate limits requests
// based on the configured limiter.
type Handler struct {
	// Limiter is the rate limiter used to limit requests.
	Limiter *rate.Limiter

	// SetRetryAfter sets the Retry-After header on rate limited
	// responses. If false, the header is not set.
	SetRetryAfter bool

	// DropOnLimit drops requests on rate limit instead of returning
	// a 429 status code. If true, the request is dropped and the
	// OnLimit handler is not called.
	DropOnLimit bool

	// OnLimit is called when a request is rate limited.
	// If nil, http.StatusTooManyRequests (429) is returned.
	OnLimit func(w http.ResponseWriter, r *http.Request)

	// Next is the Next handler in the chain.
	Next http.HandlerFunc
}

// ServeHTTP implements http.Handler and rate limits requests based
// on the configured limiter.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Limiter == nil {
		// Check if the Next handler is set.
		if h.Next != nil {
			// Call the next handler.
			h.Next(w, r)
			return
		}
		return
	}

	// Check if the request is rate limited.
	if !h.Limiter.Allow() {
		// Check if the SetRetryAfter flag is set.
		if h.SetRetryAfter {
			// Set the Retry-After header based on the limiter's
			// rate and burst. Round the duration to the nearest
			// second.
			w.Header().Set("Retry-After", h.Limiter.Reserve().Delay().Round(time.Second).String())
		}

		// Check if the OnLimit handler is set.
		if h.OnLimit != nil {
			// Call the OnLimit handler.
			h.OnLimit(w, r)
			return
		}

		// Return a 429 status code.
		http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
		return
	}

	// TODO: consider adding other X-RateLimit-* headers to the response, maybe
	// based on the limiter's rate and burst.
	//
	// See https://tools.ietf.org/html/rfc6585#section-4

	// Check if the Next handler is set.
	if h.Next != nil {
		// Call the next handler.
		h.Next(w, r)
		return
	}
}
