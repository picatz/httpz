package secureheaders

import "net/http"

// Handler is a middleware that sets common security headers on responses.
type Handler struct {
	// Next is the Next handler in the chain.
	Next http.HandlerFunc
}

// ServeHTTP implements http.Handler and sets the security headers.
func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set commonly recommended security headers.

	// Set the X-Content-Type-Options header to prevent MIME type sniffing.
	//
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// Set the X-Frame-Options header to prevent clickjacking.
	//
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
	w.Header().Set("X-Frame-Options", "DENY")

	// Set the Referrer-Policy header to prevent leaking the origin of cross-origin requests.
	//
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
	w.Header().Set("Referrer-Policy", "same-origin")

	// Set Strict-Transport-Security header to prevent downgrade attacks.
	//
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

	// Set the Content-Security-Policy header to prevent XSS attacks.
	//
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
	w.Header().Set("Content-Security-Policy", "default-src 'self'")

	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Upgrade-Insecure-Requests
	w.Header().Set("Upgrade-Insecure-Requests", "1")

	// Set the X-Permitted-Cross-Domain-Policies header to prevent Adobe Flash and Adobe Acrobat from loading content from this site.
	//
	// w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")

	// Set the Permissions-Policy header to prevent browser features.
	//
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy
	// w.Header().Set("Permissions-Policy", "accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), display-capture=(), document-domain=(), encrypted-media=(), execution-while-not-rendered=(), execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), gyroscope=(), layout-animations=(), legacy-image-formats=(), magnetometer=(), microphone=(), midi=(), navigation-override=(), oversized-images=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), sync-xhr=(), usb=()")

	// Set the Report-To header to report CSP violations. This header is ignored by browsers that don't support it.
	//
	//
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to
	// w.Header().Set("Report-To", "{\"group\":\"default\",\"max_age\":10886400,\"endpoints\":[{\"url\":\"https://example.com/endpoint\"}]}")

	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server
	// w.Header().Set("Server", "Go")

	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/SourceMap
	// w.Header().Set("SourceMap", "https://example.com/sourcemap")

	// Set the X-Download-Options header to prevent Internet Explorer from executing downloads in this site's context.
	//
	// w.Header().Set("X-Download-Options", "noopen")

	// NOTE: we don't set the X-XSS-Protection header because it
	//       is deprecated. At best, it has no effect in modern browsers.
	//
	//       At worst, it can cause XSS vulnerabilities when set.
	//
	//	     https://www.owasp.org/index.php/List_of_useful_HTTP_headers
	// w.Header().Set("X-XSS-Protection", "1; mode=block")

	// Check if the Next handler is set.
	if h.Next != nil {
		// Call the next handler.
		h.Next(w, r)
		return
	}
}
