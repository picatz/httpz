package websockets_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/picatz/httpz/pkg/websockets"
)

func TestWebsocketsFrameMask(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		frame := websockets.NewFrame(websockets.TextMessage, []byte("Hello"))

		if frame.MessageType() != websockets.TextMessage {
			t.Fatalf("expected message type to be %d, got %d", websockets.TextMessage, frame.MessageType())
		}

		if !frame.Masked() {
			t.Fatalf("expected frame to be masked")
		}

		// t.Logf("masked payload: %q", frame.Payload())

		t.Logf("%s", frame)

		payload, err := frame.Unmask()
		if err != nil {
			t.Fatal(err)
		}

		if frame.MessageType() != websockets.TextMessage {
			t.Fatalf("expected message type to be %d, got %d", websockets.TextMessage, frame.MessageType())
		}

		if !bytes.Equal(payload, []byte("Hello")) {
			t.Fatalf("expected payload to be %q, got %q", "Hello", payload)
		}
	})
}

// Run fuzz test with:
//
// $ go test -fuzz=NewFrame github.com/picatz/httpz/pkg/websockets -v
//
// Subsequent runs without the `-fuzz` flag will use the same corpus
// included in the `testdata` directory.
func FuzzNewFrame(f *testing.F) {
	// Setup a random frame.
	f.Add(websockets.NewFrame(websockets.TextMessage, []byte("Hello")).Bytes())
	f.Add(websockets.NewFrame(websockets.BinaryMessage, []byte("Hello")).Bytes())

	f.Fuzz(func(t *testing.T, frameBytes []byte) {
		frame := websockets.Frame(frameBytes)

		// Ensure the frame is not too short.
		if len(frame) < 2 {
			return
		}
		if frame[1]&0x80 == 0 {
			return
		}
		if len(frame) < 6 {
			return
		}
		if frame[1]&0x7f == 127 {
			if len(frame) < 10 {
				return
			}
		}

		// Ensure the frame is not too long.
		if len(frame) > 125 {
			return
		}

		payload, err := frame.Unmask()
		if err != nil {
			return
		}

		t.Logf("%s", payload)
	})
}

func TestReadFrame(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		frame := websockets.NewFrame(websockets.TextMessage, []byte("Hello"))

		reader := bytes.NewReader(frame.Bytes())

		frame, err := websockets.ReadFrame(reader)
		if err != nil {
			t.Fatal(err)
		}

		if frame.MessageType() != websockets.TextMessage {
			t.Fatalf("expected message type to be %d, got %d", websockets.TextMessage, frame.MessageType())
		}

		if frame.Masked() {
			t.Fatalf("expected frame to be unmasked")
		}

		if !bytes.Equal(frame.Payload(), []byte("Hello")) {
			t.Fatalf("expected payload to be %q, got %q", "Hello", frame.Payload())
		}

		t.Logf("%s", frame)
	})
}

func TestWriteFrame(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		frame := websockets.NewFrame(websockets.TextMessage, []byte("Hello"))

		writer := bytes.NewBuffer(nil)

		err := websockets.WriteFrame(writer, frame)
		if err != nil {
			t.Fatal(err)
		}

		reader := bytes.NewReader(writer.Bytes())

		frame, err = websockets.ReadFrame(reader)
		if err != nil {
			t.Fatal(err)
		}

		if frame.MessageType() != websockets.TextMessage {
			t.Fatalf("expected message type to be %d, got %d", websockets.TextMessage, frame.MessageType())
		}

		if frame.Masked() {
			t.Fatalf("expected frame to be unmasked in reader")
		}

		if !bytes.Equal(frame.Payload(), []byte("Hello")) {
			t.Fatalf("expected payload to be %q, got %q", "Hello", frame.Payload())
		}

		t.Logf("%s", frame)
	})
}

// HTTP test server.
func TestWebsockets(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websockets.Upgrade(w, r, nil)
		if err != nil {
			t.Fatal(err)
		}

		defer conn.Close()

		frame, err := conn.ReadFrame()
		if err != nil {
			if err == io.EOF {
				return
			}
			t.Fatal(err)
		}

		if frame.MessageType() == websockets.CloseMessage {
			return
		}

		if frame.MessageType() == websockets.TextMessage {
			t.Logf("received text message: %s", frame.Payload())
		}

		if frame.MessageType() == websockets.BinaryMessage {
			t.Logf("received binary message: %s", frame.Payload())
		}

		if !bytes.Equal(frame.Payload(), []byte("Hello from client")) {
			t.Fatalf("expected payload to be %q, got %q", "Hello from client", frame.Payload())
		}

		err = conn.WriteFrame(websockets.NewFrame(websockets.TextMessage, []byte("Hello from server")))
		if err != nil {
			t.Fatal(err)
		}
	}))

	defer s.Close()

	t.Run("simple", func(t *testing.T) {
		conn, _, err := websockets.Dial(context.Background(), s.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		err = conn.WriteFrame(websockets.NewFrame(websockets.TextMessage, []byte("Hello from client")))
		if err != nil {
			t.Fatal(err)
		}

		frame, err := conn.ReadFrame()
		if err != nil {
			if err == io.EOF {
				return
			}
			t.Fatal(err)
		}

		if frame.MessageType() != websockets.TextMessage {
			t.Fatalf("expected message type to be %d, got %d", websockets.TextMessage, frame.MessageType())
		}

		if !bytes.Equal(frame.Payload(), []byte("Hello from server")) {
			t.Fatalf("expected payload to be %q, got %q", "Hello", frame.Payload())
		}

		t.Logf("read frame: %s", frame)
	})
}
