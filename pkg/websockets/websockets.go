package websockets

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Conn is a WebSocket connection.
type Conn struct {
	// contains filtered or unexported fields
	raw net.Conn
	FrameReader
	FrameWriter
}

// NewConn returns a new WebSocket connection.
func NewConn(raw net.Conn) *Conn {
	return &Conn{
		raw: raw,
		FrameReader: FrameReader{
			Reader: raw,
		},
		FrameWriter: FrameWriter{
			Writer: raw,
		},
	}
}

func (c *Conn) Close() error {
	return c.raw.Close()
}

// MessageType is the type of a WebSocket message type as defined in the
// WebSocket protocol.
//
// https://tools.ietf.org/html/rfc6455#section-5.6
type MessageType int

// Message types as defined in the WebSocket protocol.
//
// https://tools.ietf.org/html/rfc6455#section-5.6
const (
	// TextMessage is a text message.
	TextMessage MessageType = 1 + iota
	// BinaryMessage is a binary message.
	BinaryMessage
	// CloseMessage is a close control message.
	CloseMessage
	// PingMessage is a ping control message.
	PingMessage
	// PongMessage is a pong control message.
	PongMessage
	// ContinuationMessage is a continuation message.
	ContinuationMessage
	// ControlMessage is a control message.
	ControlMessage
	// DataMessage is a data message.
	DataMessage
	// UnknownMessage is an unknown message.
	UnknownMessage
	// ReservedMessage is a reserved message.
	ReservedMessage
)

// String returns the string representation of the message type.
func (m MessageType) String() string {
	switch m {
	case TextMessage:
		return "TextMessage"
	case BinaryMessage:
		return "BinaryMessage"
	default:
		return fmt.Sprintf("MessageType(%d)", m)
	}
}

// WriteMessage writes a message with the given message type and payload
// using a single frame. The message type must be either TextMessage or
// BinaryMessage. The allowed message types are the same as those defined
// in the WebSocket protocol.
//
// The payload is not masked.
func (c *Conn) WriteMessage(messageType int, data []byte) error {
	frame := NewFrame(MessageType(messageType), data)
	n, err := c.raw.Write(frame)
	if err != nil {
		return err
	}
	if n != len(frame) {
		return io.ErrShortWrite
	}
	return nil
}

// SetReadDeadline sets the read deadline on the underlying connection.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.raw.SetWriteDeadline(t)
}

// SetReadDeadline sets the read deadline on the underlying connection.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.raw.SetReadDeadline(t)
}

// SetDeadline sets the read and write deadlines on the underlying connection.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.raw.SetDeadline(t)
}

// ReadMessage reads a message from the connection. The message type and
// payload are returned. The message type will be either TextMessage or
// BinaryMessage. The allowed message types are the same as those defined
// in the WebSocket protocol.
//
// The payload is unmasked.
func (c *Conn) ReadMessage() (MessageType, []byte, error) {
	frame, err := c.ReadFrame()
	if err != nil {
		return 0, nil, err
	}
	return frame.MessageType(), frame.Payload(), nil
}

// Frame is a single WebSocket frame. It is a slice of bytes that contains
// the frame header and payload. The frame header is always two bytes long.
// The first byte contains the frame type and flags. The second byte contains
// the payload length. The payload follows the header.
//
// https://tools.ietf.org/html/rfc6455#section-5.2
type Frame []byte

// FrameMask is the mask key for a masked frame.
//
// https://tools.ietf.org/html/rfc6455#section-5.3
type FrameMask [4]byte

// NewFrame creates a new frame with the given message type and payload.
// The frame is masked using a randomly generated mask key.
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-------+-+-------------+-------------------------------+
// |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
// |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
// |N|V|V|V|       |S|             |   (if payload len==126/127)   |
// | |1|2|3|       |K|             |                               |
// +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
// |     Extended payload length continued, if payload len == 127  |
// + - - - - - - - - - - - - - - - +-------------------------------+
// |                               |Masking-key, if MASK set to 1  |
// +-------------------------------+-------------------------------+
// | Masking-key (continued)       |          Payload Data         |
// +-------------------------------- - - - - - - - - - - - - - - - +
// :                     Payload Data continued ...                :
// + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
// |                     Payload Data continued ...                |
// +---------------------------------------------------------------+
//
// An example frame header:
//
//	{
//			0x81, // FIN bit set, text frame
//			0x85, // Mask bit set, payload length 5
//			0x37, 0xfa, 0x21, 0x3d, // Masking key
//			0x7f, 0x9f, 0x4d, 0x51, 0x58 // Payload
//	}
//
// https://tools.ietf.org/html/rfc6455#section-5.2
func NewFrame(messageType MessageType, payload []byte) Frame {
	// The frame header is always two bytes long, plus the masking key
	// (4 bytes) and the payload.
	frame := make(Frame, 2+4+len(payload))

	// The first byte contains the frame type and flags.
	// The frame type is the 4 least significant bits of the first byte.
	// The flags are the 4 most significant bits of the first byte.
	// The frame type must be either 1 (text) or 2 (binary).
	// The flags must be 0.
	// The frame type and flags are combined into the first byte.
	frame[0] = byte(messageType)

	// Set the FIN bit, which is the 8th bit of the first byte of the frame
	// header.
	frame[0] |= 0x80

	// The second byte contains the payload length.
	if len(payload) < 126 {
		// If the payload length is less than 126, then the payload length
		// is the 7 least significant bits of the second byte.
		frame[1] = byte(len(payload))
	} else if len(payload) < 65536 {
		// If the payload length is less than 65536, then the payload length
		// is 126 and the next two bytes contain the payload length.
		frame[1] = 126
		binary.BigEndian.PutUint16(frame[2:], uint16(len(payload)))
	} else {
		// If the payload length is greater than or equal to 65536, then the
		// payload length is 127 and the next eight bytes contain the payload
		// length.
		frame[1] = 127
		binary.BigEndian.PutUint64(frame[2:], uint64(len(payload)))
	}

	// Set the mask bit, which is the 8th bit of the second
	// byte of the frame header.
	frame[1] |= 0x80

	// Generate a random mask key, a 32-bit unsigned integer.
	//
	// https://tools.ietf.org/html/rfc6455#section-5.3
	maskKeyBytes := make([]byte, 4)
	rand.Read(maskKeyBytes)

	// Ensure the mask key is in network byte order.
	// binary.BigEndian.PutUint32(maskKey, binary.BigEndian.Uint32(maskKey))

	// Set make key bytes in frame
	copy(frame[2:], maskKeyBytes)

	// Mask the payload using the mask key.
	// This is done in place to avoid an extra allocation.
	// The mask key is repeated for each 4 bytes of the payload.
	// The mask key is XORed with the payload.
	for i := 0; i < len(payload); i++ {
		payload[i] ^= maskKeyBytes[i%4]
	}

	// Add the payload to the frame in place.
	copy(frame[6:], payload)

	return frame
}

// func (f Frame) Valid() bool {
// 	if f == nil || len(f) < 2 {
// 		return false
// 	}
//
// 	// The first byte contains the frame type and flags.
// 	// The frame type is the 4 least significant bits of the first byte.
// 	// The flags are the 4 most significant bits of the first byte.
// 	// The frame type must be either 1 (text) or 2 (binary).
// 	// The flags must be 0.
// 	// The frame type and flags are combined into the first byte.
// 	if f[0]&0x70 != 0 {
// 		return false
// 	}
//
// 	// The second byte contains the payload length.
// 	// The payload length is the 7 least significant bits of the second byte.
// 	// If the payload length is less than 126, then the payload length is the
// 	// 7 least significant bits of the second byte.
// 	// If the payload length is less than 65536, then the payload length is 126
// 	// and the next two bytes contain the payload length.
// 	// If the payload length is greater than or equal to 65536, then the
// 	// payload length is 127 and the next eight bytes contain the payload
// 	// length.
// 	payloadLength := int(f[1] & 0x7f)
// 	if payloadLength == 126 {
// 		payloadLength = int(binary.BigEndian.Uint16(f[2:4]))
// 	}
//
// 	if payloadLength == 127 {
// 		payloadLength = int(binary.BigEndian.Uint64(f[2:10]))
// 	}
//
// 	// The frame header is always two bytes long, plus the masking key
// 	// (4 bytes) and the payload.
// 	if len(f) != 2+4+payloadLength {
// 		return false
// 	}
//
// 	// The mask bit, which is the 8th bit of the second byte of the frame
// 	// header, must be set.
// 	if f[1]&0x80 == 0 {
// 		return false
// 	}
//
// 	return true
// }

func (f Frame) Bytes() []byte {
	return f
}

func (f Frame) String() string {
	payload := f.Payload()

	return fmt.Sprintf(
		"websocket.Frame{Type: %v, Size: %d, Mask:%s, Payload: %s}",
		f.MessageType(),
		len(payload),
		hex.EncodeToString(f.MaskKey()),
		hex.EncodeToString(payload),
	)
}

// MessageType returns the message type of the frame.
func (f Frame) MessageType() MessageType {
	// The message type is the 4 least significant bits of the first byte.
	return MessageType(f[0] & 0x0f)
}

// Payload returns the payload of the frame.
func (f Frame) Payload() []byte {
	if f == nil || len(f) < 2 {
		return nil
	}

	// The payload length is the 7 least significant bits of the second byte.
	payloadLength := int(f[1] & 0x7f)

	// Verify the payload length is not greater than the frame length.
	if payloadLength > len(f) {
		return nil
	}

	// If the payload length is 126, then the next two bytes contain the
	// payload length.
	if payloadLength == 126 {
		payloadLength = int(binary.BigEndian.Uint16(f[2:4]))
	}

	// If the payload length is 127, then the next eight bytes contain the
	// payload length.
	if payloadLength == 127 {
		payloadLength = int(binary.BigEndian.Uint64(f[2:10]))
	}

	// Verify the payload length is not greater than the frame length.
	if payloadLength > len(f) {
		return nil
	}

	// The payload starts after the frame header (2 bytes) and the mask key (4 bytes).
	//
	// Return the payload only, the last 6 bytes of the frame.
	return f[6:]
}

func (f Frame) PayloadSize() int {
	if f == nil || len(f) < 2 {
		return 0
	}

	// The payload length is the 7 least significant bits of the second byte.
	payloadLength := int(f[1] & 0x7f)

	// If the payload length is 126, then the next two bytes contain the
	// payload length.
	if payloadLength == 126 {
		payloadLength = int(binary.BigEndian.Uint16(f[2:4]))
	}

	// If the payload length is 127, then the next eight bytes contain the
	// payload length.
	if payloadLength == 127 {
		payloadLength = int(binary.BigEndian.Uint64(f[2:10]))
	}

	return payloadLength
}

// Masked returns true if the frame is masked.
func (f Frame) Masked() bool {
	if f == nil || len(f) < 2 {
		return false
	}
	// The mask bit is the 8th bit of the second byte.
	return f[1]&0x80 != 0
}

// MaskKey returns the mask key for the frame. The mask key is only present
// if the frame is masked.
func (f Frame) MaskKey() []byte {
	if !f.Masked() {
		return nil
	}
	return f[2:6]
}

// Unmask unmaskes the frame in place. The frame must be masked.
func (f Frame) Unmask() ([]byte, error) {
	// The mask key is the next four bytes of the frame.
	maskKey := f.MaskKey()

	// payload size
	payload := f.Payload()

	// Unmask the payload in place.
	for i := 0; i < len(payload); i++ {
		payload[i] ^= maskKey[i%4]
	}

	// Clear the mask bit.
	f[1] &^= 0x80

	// Set the unmasked masked payload in place.
	copy(f[6:], payload)

	// Return the payload only, without the mask key.
	return f[6:], nil
}

// Mask masks the frame in place. The frame must not be masked.
func (f Frame) Mask() ([]byte, error) {
	if f.Masked() {
		// return existing masked payload
		return f[6:], nil
	}

	// The mask key is the next four bytes of the frame.
	maskKey := f.MaskKey()

	// payload size
	payload := f.Payload()

	// Mask the payload in place.
	for i := 0; i < len(payload); i++ {
		payload[i] ^= maskKey[i%4]
	}

	// Set the mask bit.
	f[1] |= 0x80

	// Set the masked payload in place.
	copy(f[6:], payload)

	// Return the payload only, without the mask key.
	return f[6:], nil
}

// FrameReader reads frames from a reader.
type FrameReader struct {
	// Reader is the reader to read frames from.
	Reader io.Reader

	// MaxFrameSize is the maximum frame size allowed.
	// If the frame size is greater than MaxFrameSize, then the frame
	// is discarded and an error is returned.
	MaxFrameSize int

	// MaxPayloadSize is the maximum payload size allowed.
	// If the payload size is greater than MaxPayloadSize, then the frame
	// is discarded and an error is returned.
	MaxPayloadSize int

	// ReadTimeout is the read timeout.
	ReadTimeout time.Duration
}

// ReadFrame reads a frame from the reader.
func (r *FrameReader) ReadFrame() (Frame, error) {
	// Set deadline if the reader implements the deadline interface.
	if r.ReadTimeout > 0 {
		if d, ok := r.Reader.(interface {
			SetDeadline(time.Time) error
		}); ok {
			if err := d.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				return nil, err
			}
		}
	}

	// Read the first two bytes of the frame.
	// This contains the frame header.
	header := make([]byte, 2)
	_, err := io.ReadFull(r.Reader, header)
	if err != nil {
		return nil, err
	}

	// The payload length is the 7 least significant bits of the second byte.
	payloadLength := int(header[1] & 0x7f) // 0111 1111

	if r.MaxPayloadSize > 0 && payloadLength > r.MaxPayloadSize {
		return nil, fmt.Errorf("payload length %d exceeds maximum payload size %d", payloadLength, r.MaxPayloadSize)
	}

	if r.MaxFrameSize > 0 && payloadLength+2 > r.MaxFrameSize {
		return nil, fmt.Errorf("frame length %d exceeds maximum frame size %d", payloadLength+2, r.MaxFrameSize)
	}

	// If the payload length is 126, then the next two bytes contain the
	// payload length.
	if payloadLength == 126 {
		// Read the next two bytes of the frame.
		// This contains the extended payload length.
		extendedPayloadLength := make([]byte, 2)
		_, err := io.ReadFull(r.Reader, extendedPayloadLength)
		if err != nil {
			return nil, err
		}

		// The payload length is the next two bytes.
		payloadLength = int(binary.BigEndian.Uint16(extendedPayloadLength))
	}

	// If the payload length is 127, then the next eight bytes contain the
	// payload length.
	if payloadLength == 127 {
		// Read the next eight bytes of the frame.
		// This contains the extended payload length.
		extendedPayloadLength := make([]byte, 8)
		_, err := io.ReadFull(r.Reader, extendedPayloadLength)
		if err != nil {
			return nil, err
		}

		// The payload length is the next eight bytes.
		payloadLength = int(binary.BigEndian.Uint64(extendedPayloadLength))
	}

	// Verify the payload length is not greater than the maximum payload size.
	if r.MaxPayloadSize > 0 && payloadLength > r.MaxPayloadSize {
		return nil, fmt.Errorf("payload size %d is greater than maximum payload size %d", payloadLength, r.MaxPayloadSize)
	}

	// The mask key is the next four bytes of the frame, if the frame is masked.
	maskKey := make([]byte, 4)

	// The mask bit is the 8th bit of the second byte.
	masked := header[1]&0x80 != 0
	if masked {
		_, err := io.ReadFull(r.Reader, maskKey)
		if err != nil {
			return nil, err
		}
	}

	// The payload starts after the frame header (2 bytes) and the mask key (4 bytes).
	payload := make([]byte, payloadLength)
	_, err = io.ReadFull(r.Reader, payload)
	if err != nil {
		return nil, err
	}

	// Unmask the payload in place.
	if masked {
		for i := 0; i < len(payload); i++ {
			payload[i] ^= maskKey[i%4]
		}
	}

	// Clear the mask bit.
	header[1] &^= 0x80

	// Create the frame, copying the header, mask key (if masked) and payload.
	frame := make(Frame, 2+len(maskKey)+len(payload))
	copy(frame, header)
	copy(frame[2:], maskKey)
	copy(frame[2+len(maskKey):], payload)

	return frame, nil
}

func ReadFrame(r io.Reader) (Frame, error) {
	return (&FrameReader{
		Reader:         r,
		MaxPayloadSize: 1024 * 1024,
	}).ReadFrame()
}

// FrameWriter writes frames to a writer.
type FrameWriter struct {
	// Writer is the writer to write frames to.
	Writer io.Writer

	// Masked controls whether frames are masked.
	Masked bool
}

func (w *FrameWriter) WriteFrame(f Frame) error {
	// If the frame is masked, then unmask it.
	if !f.Masked() && w.Masked {
		_, err := f.Mask()
		if err != nil {
			return err
		}
	}

	// Write the frame to the writer.
	_, err := w.Writer.Write(f)
	return err
}

func WriteFrame(w io.Writer, f Frame) error {
	return (&FrameWriter{
		Writer: w,
		Masked: true,
	}).WriteFrame(f)
}

// Upgrade upgrades the HTTP connection to a WebSocket connection.
func Upgrade(w http.ResponseWriter, r *http.Request, additionalHeaders http.Header) (*Conn, error) {
	// Validate the request.
	if r.Method != "GET" {
		return nil, fmt.Errorf("websocket: method is not GET: %s", r.Method)
	}

	if r.Header.Get("Upgrade") != "websocket" {
		return nil, fmt.Errorf("websocket: upgrade header is not websocket: %s", r.Header.Get("Upgrade"))
	}

	if r.Header.Get("Connection") != "Upgrade" {
		return nil, fmt.Errorf("websocket: connection header is not upgrade: %s", r.Header.Get("Connection"))
	}

	// Validate the WebSocket version.
	version := r.Header.Get("Sec-WebSocket-Version")
	if version != "13" {
		return nil, fmt.Errorf("websocket: unsupported version for upgrade request %s", version)
	}

	// Validate the WebSocket key.
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, fmt.Errorf("websocket: key is empty")
	}

	// Generate the response.
	response := http.Response{
		StatusCode: 101,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}

	// Copy the response header.
	for k, v := range additionalHeaders {
		response.Header[k] = v
	}

	// Set the upgrade header.
	response.Header.Set("Upgrade", "websocket")

	// Set the connection header.
	response.Header.Set("Connection", "Upgrade")

	// https://tools.ietf.org/html/rfc6455#section-1.3
	acceptKey := func(key string) string {
		h := sha1.New()
		io.WriteString(h, key)
		io.WriteString(h, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
		return base64.StdEncoding.EncodeToString(h.Sum(nil))
	}

	// Set the WebSocket accept header.
	response.Header.Set("Sec-WebSocket-Accept", acceptKey(key))

	// Set the WebSocket protocol header.
	protocol := r.Header.Get("Sec-WebSocket-Protocol")
	if protocol != "" {
		response.Header.Set("Sec-WebSocket-Protocol", protocol)
	}

	// Set the response status.
	response.Status = fmt.Sprintf("%d %s", response.StatusCode, http.StatusText(response.StatusCode))

	// Hijack the connection.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("websocket: response does not implement http.Hijacker")
	}

	conn, _, err := hijacker.Hijack()
	if err != nil {
		return nil, err
	}

	// Write the response.
	if err := response.Write(conn); err != nil {
		return nil, err
	}

	// Return the WebSocket connection.
	return NewConn(conn), nil
}

func Dial(ctx context.Context, addr string) (*Conn, *http.Response, error) {
	d := net.Dialer{}

	// Dial the connection.
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, err
	}

	// Create the HTTP request.
	lines := []string{
		"GET / HTTP/1.1",
		"Host: " + addr,
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Key: " + base64.StdEncoding.EncodeToString([]byte("hello")),
		"Sec-WebSocket-Version: 13",
		"",
		"",
	}

	_, err = conn.Write([]byte(strings.Join(lines, "\r\n")))
	if err != nil {
		return nil, nil, err
	}

	// Decode the response.
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, nil, err
	}

	// Validate the response.
	if resp.StatusCode != 101 {
		return nil, resp, fmt.Errorf("websocket: unexpected status code: %d", resp.StatusCode)
	}

	if resp.Header.Get("Upgrade") != "websocket" {
		return nil, resp, fmt.Errorf("websocket: upgrade header is not websocket: %s", resp.Header.Get("Upgrade"))
	}

	if resp.Header.Get("Connection") != "Upgrade" {
		return nil, resp, fmt.Errorf("websocket: connection header is not upgrade: %s", resp.Header.Get("Connection"))
	}

	// Validate the WebSocket version.
	// version := resp.Header.Get("Sec-WebSocket-Version")
	// if version != "13" {
	// 	return nil, resp, fmt.Errorf("websocket: unsupported version for upgrade response: %s", version)
	// }

	// Validate the WebSocket key.
	accept := resp.Header.Get("Sec-WebSocket-Accept")
	if accept == "" {
		return nil, resp, fmt.Errorf("websocket: accept is empty")
	}

	// Return the WebSocket connection.
	return NewConn(conn), resp, nil
}
