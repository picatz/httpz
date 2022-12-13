// Package oauth2 provides a set of functionality for using OAuth 2.0
// to implement authorization for resource provided by HTTP services.
//
// Can be used to implement an authorization server to provide access
// tokens to clients, or to implement a client to obtain access tokens
// from an authorization server.
//
// The package is designed to be used with the standard library's
// http package, and can be used with any http.Handler or http.RoundTripper
// implementation.
//
// It is as complete as possible, trying to implement all the features
// of the OAuth 2.0 specification, including the extensions for
// client credentials, resource owner password credentials, and
// refresh tokens.
//
// It is designed with the following goals in mind:
//
// 1. Provide a complete implementation of the OAuth 2.0 specification.
//
//  2. Provide a complete implementation of the OAuth 2.0 extensions for
//     client credentials, resource owner password credentials, and
//     refresh tokens.
//
//  3. Provide a complete implementation of the OAuth 2.0 extensions for
//     JWT access tokens and JWT bearer tokens.
//
//  4. Provide a complete implementation of the OAuth 2.0 extensions for
//     the PKCE extension.
//
//  5. Provide a complete implementation of the OAuth 2.0 extensions for
//     the Device Authorization Grant.
//
//  6. Provide a complete implementation of the OAuth 2.0 extensions for
//     the Token Exchange extension.
//
//  7. Provide a complete implementation of the OAuth 2.0 extensions for
//     the Token Introspection extension.
//
//  8. Provide a complete implementation of the OAuth 2.0 extensions for
//     the Token Revocation extension.
//
//  9. Be as secure as possible by default.
package oauth2
