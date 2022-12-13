package oauth2

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/picatz/jose/pkg/jwk"
)

// AuthorizationServer is the OAuth 2.0 authorization server.
//
// The authorization server is responsible for issuing access tokens
// to clients after they have obtained authorization from the resource
// owner. The authorization server also issues refresh tokens, which
// can be used to obtain new access tokens after the current access
// token has expired.
//
// The authorization server is also responsible for validating access
// tokens presented by clients to protected resources.
//
// The authorization server is also responsible for validating client
// assertions presented by clients to protected resources. Client
// are simply JWTs signed by the client's private key and contain
// information about the client.
type AuthorizationServer struct {
	// contains filtered or unexported fields

	// Keys is the sets of keys used to sign and verify tokens.
	Keys jwk.Set

	// TokenStore is the store used to persist tokens.
	TokenStore Store[Token]

	// ClientStore is the store used to persist clients.
	ClientStore Store[Client]

	// UserStore is the store used to persist users.
	UserStore Store[User]

	// AuthorizeCodeStore is the store used to persist authorize codes.
	AuthorizeCodeStore Store[AuthorizeCode]

	// AccessTokenStore is the store used to persist access tokens.
	AccessTokenStore Store[AccessToken]

	// RefreshTokenStore is the store used to persist refresh tokens.
	RefreshTokenStore Store[RefreshToken]

	// DeviceCodeStore is the store used to persist device codes.
	DeviceCodeStore Store[DeviceCode]

	// ClientAssertionStore is the store used to persist client assertions.
	ClientAssertionStore Store[ClientAssertion]

	// ClientAssertionPrivateKeyStore is the store used to persist client assertion private keys.
	ClientAssertionPrivateKeyStore Store[ClientAssertionPrivateKey]
}

// NewAuthorizationServer returns a new OAuth 2.0 authorization server
// with the given options.
func NewAuthorizationServer(opts ...AuthorizationServerOption) *AuthorizationServer {
	// Create a new authorization server.
	s := &AuthorizationServer{}

	// Apply the options.
	for _, opt := range opts {
		opt(s)
	}

	// Return the authorization server.
	return s
}

type AuthorizationServerOption func(*AuthorizationServer)

// WithAuthorizationServerKeys sets the keys used to sign and verify tokens.
func WithAuthorizationServerKeys(keys jwk.Set) AuthorizationServerOption {
	return func(s *AuthorizationServer) {
		s.Keys = keys
	}
}

// WithAuthorizationServerTokenStore sets the store used to persist tokens.
func WithAuthorizationServerTokenStore(store Store[Token]) AuthorizationServerOption {
	return func(s *AuthorizationServer) {
		s.TokenStore = store
	}
}

// WithAuthorizationServerClientStore sets the store used to persist clients.
func WithAuthorizationServerClientStore(store Store[Client]) AuthorizationServerOption {
	return func(s *AuthorizationServer) {
		s.ClientStore = store
	}
}

// WithAuthorizationServerUserStore sets the store used to persist users.
func WithAuthorizationServerUserStore(store Store[User]) AuthorizationServerOption {
	return func(s *AuthorizationServer) {
		s.UserStore = store
	}
}

// WithAuthorizationServerAuthorizeCodeStore sets the store used to persist authorize codes.
func WithAuthorizationServerAuthorizeCodeStore(store Store[AuthorizeCode]) AuthorizationServerOption {
	return func(s *AuthorizationServer) {
		s.AuthorizeCodeStore = store
	}
}

// WithAuthorizationServerAccessTokenStore sets the store used to persist access tokens.
func WithAuthorizationServerAccessTokenStore(store Store[AccessToken]) AuthorizationServerOption {
	return func(s *AuthorizationServer) {
		s.AccessTokenStore = store
	}
}

// WithAuthorizationServerRefreshTokenStore sets the store used to persist refresh tokens.
func WithAuthorizationServerRefreshTokenStore(store Store[RefreshToken]) AuthorizationServerOption {
	return func(s *AuthorizationServer) {
		s.RefreshTokenStore = store
	}
}

// WithAuthorizationServerDeviceCodeStore sets the store used to persist device codes.
func WithAuthorizationServerDeviceCodeStore(store Store[DeviceCode]) AuthorizationServerOption {
	return func(s *AuthorizationServer) {
		s.DeviceCodeStore = store
	}
}

// WithAuthorizationServerClientAssertionStore sets the store used to persist client assertions.
func WithAuthorizationServerClientAssertionStore(store Store[ClientAssertion]) AuthorizationServerOption {
	return func(s *AuthorizationServer) {
		s.ClientAssertionStore = store
	}
}

// WithAuthorizationServerClientAssertionPrivateKeyStore sets the store used to persist client assertion private keys.
func WithAuthorizationServerClientAssertionPrivateKeyStore(store Store[ClientAssertionPrivateKey]) AuthorizationServerOption {
	return func(s *AuthorizationServer) {
		s.ClientAssertionPrivateKeyStore = store
	}
}

var (
	ErrInvalidRequest = errors.New("invalid oauth2 request")
	ErrInvalidClient  = errors.New("invalid oauth2 client")
	ErrInvalidGrant   = errors.New("invalid oauth2 grant")
	ErrUnauthorized   = errors.New("unauthorized oauth2 request")
	ErrUnsupported    = errors.New("unsupported oauth2 request")
	ErrInvalidScope   = errors.New("invalid oauth2 scope")
	ErrServerError    = errors.New("oauth2 authorization server error")
)

// AuthorizeError is an error returned by the authorization server.
type AuthorizeError struct {
	// contains filtered or unexported fields

	// Err is the error.
	Err error

	// RedirectURI is the redirect URI.
	RedirectURI string

	// State is the state.
	State string

	// Code is the error code.
	Code int

	// Description is the error description.
	Description string

	// URI is the error URI.
	URI string

	// Headers are the headers.
	Headers http.Header

	// Status is the status.
	Status int
}

func (e *AuthorizeError) Error() string {
	return e.Err.Error()
}

// HandleAuthorize handles an authorize request.
//
// The authorization endpoint is used to interact with the resource
// owner and obtain an authorization grant. The authorization grant
// is used to obtain an access token.
//
// The authorization endpoint is used by the client to obtain an
// authorization grant from the resource owner via user-agent
// redirection.
func (s *AuthorizationServer) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Parse the request.
	req, err := ParseAuthorizeRequest(r)
	if err != nil {
		s.WriteAuthorizeError(w, err)
		return
	}

	// Validate the request.
	err = s.ValidateAuthorizeRequest(req)
	if err != nil {
		s.WriteAuthorizeError(w, err)
		return
	}

	// Handle the request.
	err = s.HandleAuthorizeRequest(w, r, req)
	if err != nil {
		s.WriteAuthorizeError(w, err)
		return
	}
}

// WriteAuthorizeError writes an authorize error.
func (s *AuthorizationServer) WriteAuthorizeError(w http.ResponseWriter, err error) {
	// Check if the error is an authorize error.
	if e, ok := err.(*AuthorizeError); ok {
		// Write the error.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(e.Code)
		json.NewEncoder(w).Encode(e)
		return
	}

	// Check if the error is an OAuth 2.0 error.
	if e, ok := err.(*Error); ok {
		// Write the error.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(e.StatusCode)
		json.NewEncoder(w).Encode(e)
		return
	}

	// Write the error.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(&Error{
		StatusCode: http.StatusInternalServerError,
		ErrorType:  "server_error",
		Error:      "server_error",
		Description: fmt.Sprintf(
			"An internal server error occurred: %s",
			err.Error(),
		),
	})
}

// ParseAuthorizeRequest parses the authorize request.
func ParseAuthorizeRequest(r *http.Request) (*AuthorizeRequest, error) {
	// Extract the query parameters.
	q := r.URL.Query()

	// Extract the client ID.
	clientID := q.Get("client_id")

	// Extract the redirect URI.
	redirectURI := q.Get("redirect_uri")

	// Extract the scope.
	scope := q.Get("scope")

	// Extract the state.
	state := q.Get("state")

	// Extract the nonce.
	nonce := q.Get("nonce")

	// Extract the code challenge.
	codeChallenge := q.Get("code_challenge")

	// Extract the code challenge method.
	codeChallengeMethod := q.Get("code_challenge_method")

	// Extract the device code.
	deviceCode := q.Get("device_code")

	// Extract the device code challenge.
	deviceCodeChallenge := q.Get("device_code_challenge")

	// Extract the device code challenge method.
	deviceCodeChallengeMethod := q.Get("device_code_challenge_method")

	// Create the request.
	req := &AuthorizeRequest{
		Request:                   r,
		ClientID:                  clientID,
		RedirectURI:               redirectURI,
		Scope:                     scope,
		State:                     state,
		Nonce:                     nonce,
		CodeChallenge:             codeChallenge,
		CodeChallengeMethod:       codeChallengeMethod,
		DeviceCode:                deviceCode,
		DeviceCodeChallenge:       deviceCodeChallenge,
		DeviceCodeChallengeMethod: deviceCodeChallengeMethod,
	}

	// Return the request.
	return req, nil
}

// ValidateAuthorizeRequest validates the authorize request.
func (s *AuthorizationServer) ValidateAuthorizeRequest(req *AuthorizeRequest) error {
	// Check if the client ID is set.
	if req.ClientID == "" {
		return &AuthorizeError{
			Err:         ErrInvalidRequest,
			Code:        http.StatusBadRequest,
			RedirectURI: req.RedirectURI,
			State:       req.State,
		}
	}

	// Check if the redirect URI is set.
	if req.RedirectURI == "" {
		return &AuthorizeError{
			Err:         ErrInvalidRequest,
			Code:        http.StatusBadRequest,
			RedirectURI: req.RedirectURI,
			State:       req.State,
		}
	}

	// Check if the client is valid.
	client, err := s.ClientStore.Get(req.ClientID)
	if err != nil {
		return &AuthorizeError{
			Err:         ErrInvalidClient,
			Code:        http.StatusBadRequest,
			RedirectURI: req.RedirectURI,
			State:       req.State,
		}
	}

	// Check if the client is authorized.
	if !client.IsAuthorized() {
		return &AuthorizeError{
			Err:         ErrUnauthorized,
			Code:        http.StatusBadRequest,
			RedirectURI: req.RedirectURI,
			State:       req.State,
		}
	}

	// Check if the redirect URI is valid.
	if !client.IsRedirectURIValid(req.RedirectURI) {
		return &AuthorizeError{
			Err:         ErrInvalidRequest,
			Code:        http.StatusBadRequest,
			RedirectURI: req.RedirectURI,
			State:       req.State,
		}
	}

	// Check if the scope is valid.
	// if !client.IsScopeValid(req.Scope) {
	// 	return &AuthorizeError{
	// 		Err:         ErrInvalidScope,
	// 		Code:        http.StatusBadRequest,
	// 		RedirectURI: req.RedirectURI,
	// 		State:       req.State,
	// 	}
	// }

	// Check if the code challenge is set.
	if req.CodeChallenge != "" {
		// Check if the code challenge method is set.
		if req.CodeChallengeMethod == "" {
			return &AuthorizeError{
				Err:         ErrInvalidRequest,
				Code:        http.StatusBadRequest,
				RedirectURI: req.RedirectURI,
				State:       req.State,
			}
		}

		// Check if the code challenge method is valid.
		if !client.IsCodeChallengeMethodValid(req.CodeChallengeMethod) {
			return &AuthorizeError{
				Err:         ErrInvalidRequest,
				Code:        http.StatusBadRequest,
				RedirectURI: req.RedirectURI,
				State:       req.State,
			}
		}
	}

	// Check if the device code is set.
	if req.DeviceCode != "" {
		// Check if the device code challenge is set.
		if req.DeviceCodeChallenge != "" {
			// Check if the device code challenge method is set.
			if req.DeviceCodeChallengeMethod == "" {
				return &AuthorizeError{
					Err:         ErrInvalidRequest,
					Code:        http.StatusBadRequest,
					RedirectURI: req.RedirectURI,
					State:       req.State,
				}
			}

			// Check if the device code challenge method is valid.
			if !client.IsDeviceCodeChallengeMethodValid(req.DeviceCodeChallengeMethod) {
				return &AuthorizeError{
					Err:         ErrInvalidRequest,
					Code:        http.StatusBadRequest,
					RedirectURI: req.RedirectURI,
					State:       req.State,
				}
			}
		}
	}

	// Return no error.
	return nil
}

// HandleAuthorizeRequest handles the authorize request.
func (s *AuthorizationServer) HandleAuthorizeRequest(w http.ResponseWriter, r *http.Request) {
	// Parse the authorize request.
	req, err := s.ParseAuthorizeRequest(r)
	if err != nil {
		// Check if the error is an authorize error.
		if err, ok := err.(*AuthorizeError); ok {
			// Redirect the user to the redirect URI with the error.
			http.Redirect(w, r, err.RedirectURI, http.StatusFound)
			return
		}

		// Return the error.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate the authorize request.
	err = s.ValidateAuthorizeRequest(req)
	if err != nil {
		// Check if the error is an authorize error.
		if err, ok := err.(*AuthorizeError); ok {
			// Redirect the user to the redirect URI with the error.
			http.Redirect(w, r, err.RedirectURI, http.StatusFound)
			return
		}

		// Return the error.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if the user is not logged in.
	if req.User == nil {
		// Redirect the user to the login page.
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Check if the user is not authorized.
	if !req.User.IsAuthorized() {

		// Redirect the user to the login page.
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Check if the user is not authorized for the client.
	if !req.User.IsAuthorizedForClient(req.ClientID) {
		// Redirect the user to the login page.
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Check if the user is not authorized for the scope.
	if !req.User.IsAuthorizedForScope(req.Scope) {
		// Redirect the user to the login page.
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Check if the user is not authorized for the redirect URI.
	if !req.User.IsAuthorizedForRedirectURI(req.RedirectURI) {
		// Redirect the user to the login page.
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Check if the user is not authorized for the nonce.
	if !req.User.IsAuthorizedForNonce(req.Nonce) {
		// Redirect the user to the login page.
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Check if the user is not authorized for the code challenge.
	if !req.User.IsAuthorizedForCodeChallenge(req.CodeChallenge) {
		// Redirect the user to the login page.
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Check if the user is not authorized for the code challenge method.
	if !req.User.IsAuthorizedForCodeChallengeMethod(req.CodeChallengeMethod) {
		// Redirect the user to the login page.
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}


	// Check if the user is not authorized for the device code.
	if !req.User.IsAuthorizedForDeviceCode(req.DeviceCode) {
		// Redirect the user to the login page.
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Check if the user is not authorized for the device code challenge.
	if !req.User.IsAuthorizedForDeviceCodeChallenge(req.DeviceCodeChallenge) {
		// Redirect the user to the login page.
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Check if the user is not authorized for the device code challenge method.
	if !req.User.IsAuthorizedForDeviceCodeChallengeMethod(req.DeviceCodeChallengeMethod) {
		// Redirect the user to the login page.
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Check if the request is a device code request.
	if req.DeviceCode != "" {
			// Check if the device code is not authorized.
			if !req.User.IsDeviceCodeAuthorized(req.DeviceCode) {
				// Redirect the user to the login page.
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}

		}

type AuthorizeRequest struct {
	// Request is the underlying HTTP request.
	Request *http.Request

	// Client is the client making the request.
	ClientID string

	// User is the user making the request.
	// User *User

	// Scope is the scope of the request.
	Scope string

	// State is the state of the request.
	State string

	// RedirectURI is the redirect URI of the request.
	RedirectURI string

	// Nonce is the nonce of the request.
	Nonce string

	// CodeChallenge is the code challenge of the request.
	CodeChallenge string

	// CodeChallengeMethod is the code challenge method of the request.
	CodeChallengeMethod string

	// DeviceCode is the device code of the request.
	DeviceCode string

	// DeviceCodeChallenge is the device code challenge of the request.
	DeviceCodeChallenge string

	// DeviceCodeChallengeMethod is the device code challenge method of the request.
	DeviceCodeChallengeMethod string
}

// Store is the interface used to persist items of the given type
// to a persistent storage backend.
//
// Backends can be in-memory, file-based, or database-based. It
// is responsible for generating the ID of the item.
type Store[T any] interface {
	// Get returns the item with the given ID.
	Get(id string) (*T, error)
	// Create creates a new item.
	Create(item *T) error
	// Delete deletes the item with the given ID.
	Delete(id string) error
	// DeleteExpired deletes all expired items.
	// DeleteExpired() error
	// DeleteMatch deletes all items matching the given filter.
	// DeleteMatch(filter Filter[T]) error
	// List returns the list of items, using the given filter.
	List(filter Filter[T]) ([]*T, error)
	// Close closes the store and releases any resources, such as
	// database connections.
	Close() error
}

// Filter is the filter function used to match items.
//
// It returns true if the item matches the filter, false otherwise.
type Filter[T any] func(item *T) bool

// Token describes an OAuth 2.0 token.
//
// https://tools.ietf.org/html/rfc6749#section-1.4
type Token struct {
	// ID is the token ID.
	ID string

	// ClientID is the client ID.
	ClientID string

	// UserID is the user ID.
	UserID string

	// Scopes is the list of scopes.
	Scopes []string

	// CreatedAt is the creation time.
	CreatedAt time.Time

	// ExpiresAt is the expiration time.
	ExpiresAt time.Time

	// Claims is the list of claims.
	Claims map[string]interface{}

	// Extra is the list of extra data.
	Extra map[string]interface{}
}

// Client is the client.
type Client struct {
	// ID is the client ID.
	ID string

	// Secret is the client secret.
	Secret string

	// RedirectURIs is the list of redirect URIs.
	RedirectURIs []string

	// Scopes is the list of scopes.
	Scopes []string

	// GrantTypes is the list of grant types.
	GrantTypes []string

	// ResponseTypes is the list of response types.
	ResponseTypes []string

	// ACRValues is the list of ACR values.
	ACRValues []string

	// TokenEndpointAuthMethod is the token endpoint auth method.
	TokenEndpointAuthMethod string

	// TokenEndpointAuthSigningAlg is the token endpoint auth signing algorithm.
	TokenEndpointAuthSigningAlg string

	// JWKS is the JSON Web Key Set.
	JWKS jwk.Set

	// JWKSURI is the JSON Web Key Set URI.
	JWKSURI string

	// PolicyURI is the policy URI.
	PolicyURI string

	// TermsOfServiceURI is the terms of service URI.
	TermsOfServiceURI string

	// ClientName is the client name.
	ClientName string

	// LogoURI is the logo URI.
	LogoURI string

	// ClientURI is the client URI.
	ClientURI string

	// Contacts is the list of contacts.
	Contacts []string

	// SectorIdentifierURI is the sector identifier URI.
	SectorIdentifierURI string

	// SubjectType is the subject type.
	SubjectType string
}

// IsAuthorized returns true if the client is authorized to use the given scope.
func (c *Client) IsAuthorized(scope string) bool {
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// IsRedirectURIValid returns true if the given redirect URI is valid.
func (c *Client) IsRedirectURIValid(redirectURI string) bool {
	for _, uri := range c.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

// IsCodeChallengeMethodValid returns true if the given code challenge method is valid.
func (c *Client) IsCodeChallengeMethodValid(codeChallengeMethod string) bool {
	switch codeChallengeMethod {
	case "plain", "S256":
		return true
	default:
		return false
	}
}

// IsDeviceCodeChallengeMethodValid returns true if the given device code challenge method is valid.
func (c *Client) IsDeviceCodeChallengeMethodValid(deviceCodeChallengeMethod string) bool {
	switch deviceCodeChallengeMethod {
	case "plain", "S256":
		return true
	default:
		return false
	}
}

// IsAuthorized returns true if the client is authorized to use the given grant type.
func (c *Client) IsAuthorizedGrantType(grantType string) bool {
	for _, t := range c.GrantTypes {
		if t == grantType {
			return true
		}
	}
	return false
}

type User struct {
	// ID is the user ID.
	ID string

	// Username is the username.
	Username string

	// Password is the password.
	Password string

	// Scopes is the list of scopes.
	Scopes []string

	// Claims is the list of claims.
	Claims map[string]interface{}

	// Extra is the list of extra data.
	Extra map[string]interface{}

	// Enabled is true if the user is enabled.
	Enabled bool
}

type AuthorizeCode struct {
	// ID is the authorize code ID.
	ID string

	// ClientID is the client ID.
	ClientID string

	// UserID is the user ID.
	UserID string

	// Scopes is the list of scopes.
	Scopes []string

	// RedirectURI is the redirect URI.
	RedirectURI string

	// Nonce is the nonce.
	Nonce string

	// CodeChallenge is the code challenge.
	CodeChallenge string

	// CodeChallengeMethod is the code challenge method.
	CodeChallengeMethod string

	// CreatedAt is the creation time.
	CreatedAt time.Time

	// ExpiresAt is the expiration time.
	ExpiresAt time.Time

	// Claims is the list of claims.
	Claims map[string]interface{}

	// Extra is the list of extra data.
	Extra map[string]interface{}

	// CodeChallengeS256 is the code challenge S256.
	CodeChallengeS256 string

	// CodeChallengePlain is the code challenge plain.
	CodeChallengePlain string

	// CodeChallengeNone is the code challenge none.
	CodeChallengeNone string
}

type AccessToken struct {
	// ID is the access token ID.
	ID string

	// ClientID is the client ID.
	ClientID string

	// UserID is the user ID.
	UserID string

	// Scopes is the list of scopes.
	Scopes []string

	// CreatedAt is the creation time.
	CreatedAt time.Time

	// ExpiresAt is the expiration time.
	ExpiresAt time.Time

	// Claims is the list of claims.
	Claims map[string]interface{}

	// Extra is the list of extra data.
	Extra map[string]interface{}
}

type RefreshToken struct {
	// ID is the refresh token ID.
	ID string

	// ClientID is the client ID.
	ClientID string

	// UserID is the user ID.
	UserID string

	// Scopes is the list of scopes.
	Scopes []string

	// CreatedAt is the creation time.
	CreatedAt time.Time

	// ExpiresAt is the expiration time.
	ExpiresAt time.Time

	// Claims is the list of claims.
	Claims map[string]interface{}

	// Extra is the list of extra data.
	Extra map[string]interface{}
}

type DeviceCode struct {
	// ID is the device code ID.
	ID string

	// DeviceCode is the device code.
	DeviceCode string

	// UserCode is the user code.
	UserCode string

	// ClientID is the client ID.
	ClientID string

	// Scopes is the list of scopes.
	Scopes []string

	// RedirectURI is the redirect URI.
	RedirectURI string

	// CreatedAt is the creation time.
	CreatedAt time.Time

	// ExpiresAt is the expiration time.
	ExpiresAt time.Time

	// Claims is the list of claims.
	Claims map[string]interface{}

	// Extra is the list of extra data.
	Extra map[string]interface{}

	// Interval is the interval.
	Interval int

	// UserCodeExpiresAt is the user code expiration time.
	UserCodeExpiresAt time.Time

	// VerificationURI is the verification URI.
	VerificationURI string

	// VerificationURIComplete is the verification URI complete.
	VerificationURIComplete string

	// VerificationURICompleteWithParams is the verification URI complete with params.
	VerificationURICompleteWithParams string

	// DeviceCodeExpiresAt is the device code expiration time.
	DeviceCodeExpiresAt time.Time

	// PollInterval is the poll interval.
	PollInterval int
}

// ClientAssertion is the client assertion.
//
// https://tools.ietf.org/html/rfc7521#section-4.2
type ClientAssertion struct {
	// ID is the client assertion ID.
	ID string

	// ClientID is the client ID.
	ClientID string

	// UserID is the user ID.
	UserID string

	// Scopes is the list of scopes.
	Scopes []string

	// CreatedAt is the creation time.
	CreatedAt time.Time

	// ExpiresAt is the expiration time.
	ExpiresAt time.Time

	// Claims is the list of claims.
	Claims map[string]interface{}

	// Extra is the list of extra data.
	Extra map[string]interface{}

	// Assertion is the assertion.
	Assertion string

	// AssertionType is the assertion type.
	AssertionType string

	// AssertionFormat is the assertion format.
	AssertionFormat string
}

// ClientAssertionPrivateKey is the client assertion private key.
//
// https://tools.ietf.org/html/rfc7521#section-4.2
type ClientAssertionPrivateKey struct {
	// ID is the client assertion private key ID.
	ID string

	// ClientID is the client ID.
	ClientID string

	// UserID is the user ID.
	UserID string

	// Scopes is the list of scopes.
	Scopes []string

	// CreatedAt is the creation time.
	CreatedAt time.Time

	// ExpiresAt is the expiration time.
	ExpiresAt time.Time

	// Claims is the list of claims.
	Claims map[string]interface{}

	// Extra is the list of extra data.
	Extra map[string]interface{}

	// PrivateKey is the private key.
	PrivateKey []byte

	// PrivateKeyFormat is the private key format.
	PrivateKeyFormat string

	// PrivateKeyAlgorithm is the private key algorithm.
	PrivateKeyAlgorithm string
}
