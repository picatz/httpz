package cookies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"
)

func New(name, value string, key any) (*Cookie, error) {
	c := &Cookie{
		Name:  name,
		Value: value,
	}

	switch key := key.(type) {
	case []byte: // AES
		err := c.Encrypt(key)
		if err != nil {
			return nil, err
		}
	case *rsa.PrivateKey: // RSA
		err := c.Encrypt(key)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid key type %T", key)
	}

	return c, nil
}

// Cookie is a wrapper around http.Cookie that provides a more convenient
// way to set cookies with options.
type Cookie struct {
	Name  string
	Value string

	encrypted bool
}

func (c *Cookie) Decrypt(r *http.Request, key []byte) error {
	cookie, err := r.Cookie(c.Name)
	if err != nil {
		return err
	}

	dec, err := decryptAES(cookie.Value, key)
	if err != nil {
		return err
	}

	c.Value = dec

	c.encrypted = false

	return nil
}

func Get(r *http.Request, name string, key any) (*Cookie, error) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get cookie %q: %w", name, err)
	}

	// decrypt if key is provided based on the cookie type
	switch key := key.(type) {
	case []byte: // AES
		dec, err := decryptAES(cookie.Value, key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt cookie %q using AES: %w", name, err)
		}

		return &Cookie{
			Name:  name,
			Value: dec,
		}, nil
	case *rsa.PrivateKey: // RSA
		dec, err := decryptRSA(cookie.Value, key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt cookie %q using RSA: %w", name, err)
		}

		return &Cookie{
			Name:  name,
			Value: dec,
		}, nil
	}

	return &Cookie{
		Name:  name,
		Value: cookie.Value,
	}, nil
}

func (c *Cookie) Encrypt(key any) error {

	switch key := key.(type) {
	case []byte: // AES

		enc, err := encryptAES(c.Value, key)
		if err != nil {
			return err
		}

		c.encrypted = true

		c.Value = enc
	case *rsa.PrivateKey: // RSA

		enc, err := encryptRSA(c.Value, key)
		if err != nil {
			return err
		}

		c.encrypted = true

		c.Value = enc
	default:
		return fmt.Errorf("invalid key type %T", key)
	}

	return nil
}

func (c *Cookie) String() string {
	return c.Name + "=" + c.Value
}

func (c *Cookie) SetResponse(w http.ResponseWriter, options ...Option) error {
	cookie := &http.Cookie{
		Name:  c.Name,
		Value: c.Value,
	}

	for _, option := range options {
		option(cookie)
	}

	http.SetCookie(w, cookie)
	return nil
}

type Option func(*http.Cookie) error

func WithDomain(domain string) Option {
	return func(cookie *http.Cookie) error {
		cookie.Domain = domain
		return nil
	}
}

func WithPath(path string) Option {
	return func(cookie *http.Cookie) error {
		cookie.Path = path
		return nil
	}
}

func WithMaxAge(maxAge int) Option {
	return func(cookie *http.Cookie) error {
		cookie.MaxAge = maxAge
		return nil
	}
}

func WithSecure(secure bool) Option {
	return func(cookie *http.Cookie) error {
		cookie.Secure = secure
		return nil
	}
}

func WithHttpOnly(httpOnly bool) Option {
	return func(cookie *http.Cookie) error {
		cookie.HttpOnly = httpOnly
		return nil
	}
}

func WithSameSite(sameSite http.SameSite) Option {
	return func(cookie *http.Cookie) error {
		cookie.SameSite = sameSite
		return nil
	}
}

func WithExpires(expires time.Time) Option {
	return func(cookie *http.Cookie) error {
		cookie.Expires = expires
		return nil
	}
}

func WithRawExpires(rawExpires string) Option {
	return func(cookie *http.Cookie) error {
		cookie.RawExpires = rawExpires
		return nil
	}
}

func WithUnparsed(unparsed []string) Option {
	return func(cookie *http.Cookie) error {
		cookie.Unparsed = unparsed
		return nil
	}
}

func WithRaw(raw string) Option {
	return func(cookie *http.Cookie) error {
		cookie.Raw = raw
		return nil
	}
}

func WithEncrytionKeyAES(key []byte) Option {
	return func(cookie *http.Cookie) error {
		// Encrypt cookie value with the given AES 256 key in GCM mode.
		// The key must be 32 bytes.
		enc, err := encryptAES(cookie.Value, key)
		if err != nil {
			return err
		}
		cookie.Value = enc
		return nil
	}
}

func WithEncrytionKeyRSA(key *rsa.PrivateKey) Option {
	return func(cookie *http.Cookie) error {
		// Encrypt cookie value with the given RSA private key.
		enc, err := encryptRSA(cookie.Value, key)
		if err != nil {
			return err
		}
		cookie.Value = enc
		return nil
	}
}

// encryptAES encrypts the given value with the given AES 256 key in GCM mode.
// The key must be 32 bytes.
func encryptAES(value string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(value))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to read random bytes for IV: %w", err)
	}

	stream, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	ciphertext = stream.Seal(iv, iv, []byte(value), nil)

	return fmt.Sprintf("%x", ciphertext), nil
}

// decryptAES decrypts the given value with the given AES 256 key in GCM mode.
// The key must be 32 bytes.
func decryptAES(value string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	ciphertext, err := hex.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex string: %w", err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	ca, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	plaintext, err := ca.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

func WithEncytionKeyRSA(key *rsa.PrivateKey) Option {
	return func(cookie *http.Cookie) error {
		// Encrypt cookie value with the given RSA private key.
		enc, err := encryptRSA(cookie.Value, key)
		if err != nil {
			return err
		}
		cookie.Value = enc
		return nil
	}
}

// encryptRSA encrypts the given value with the given RSA private key.
func encryptRSA(value string, key *rsa.PrivateKey) (string, error) {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, []byte(value), nil)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}

	return fmt.Sprintf("%x", ciphertext), nil
}

// decryptRSA decrypts the given value with the given RSA private key.
func decryptRSA(value string, key *rsa.PrivateKey) (string, error) {
	ciphertext, err := hex.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("failed to decode hex string: %w", err)
	}

	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// SetRequest sets the given cookie to the given request.
func (c *Cookie) SetRequest(r *http.Request, opts ...Option) {
	hc := &http.Cookie{
		Name:  c.Name,
		Value: c.Value,
	}

	for _, opt := range opts {
		if err := opt(hc); err != nil {
			return
		}
	}

	r.AddCookie(hc)

}
