# httpz

Collection of packages that extend `net/http` functionality.

| Package          | Description                                                                            |
|:-----------------|:---------------------------------------------------------------------------------------|
| `websocket`      | Implements the WebSocket protocol ([RFC6455](https://www.rfc-editor.org/rfc/rfc6455)). |
| `ratelimit`      | Rate limiting middleware.                                                              |
| `secureheaders`  | Common security HTTP response header middleware.                                       |

### Websocket

```go
hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    conn, _ := websocket.Upgrade(w, r, nil)
    defer conn.Close()

    for {
        frame, _ := conn.ReadFrame()

        switch frame.Type() {
        case websocket.TextFrame:
            slog.Info("recvd text frame", "payload" frame.Payload())
        case websocket.CloseFrame:
            return
        default:
            // handle other types
        }
    }
})
```