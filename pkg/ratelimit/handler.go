package ratelimit

import (
	"fmt"
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

	// SetXLimit sets the X-RateLimit-* headers on rate limited
	SetXLimit bool

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
			//
			// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After
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

	// Optional common rate limit headers.
	//
	// https://developer.okta.com/docs/reference/rl-best-practices/#check-your-rate-limits-with-okta-s-rate-limit-headers
	if h.SetXLimit {
		// The rate limit ceiling that is applicable for the current request.
		w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", int(h.Limiter.Limit())))
		// The number of requests left for the current rate-limit window.
		w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", int(h.Limiter.Burst())-int(h.Limiter.Limit())))
		// The time at which the rate limit resets, specified in UTC epoch time (in seconds).
		w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(h.Limiter.Reserve().Delay()).Unix()))
	}

	// Check if the Next handler is set.
	if h.Next != nil {
		// Call the next handler.
		h.Next(w, r)
		return
	}
}
