// Package websocket provides a simple interface to the WebSocket protocol.
//
// WebSockets are a way to have a persistent connection between a browser and a
// server.
//
// This is useful for applications that want to have a two-way
// communication channel with the browser.
//
// Diagram
//
//	+----------------+                          +----------------+
//	|     Client     |                          |     Server     |
//	+----------------+                          +----------------+
//	         |                                           |
//	         |------------ GET /chat HTTP/1.1 ---------->|
//	         |                                           |
//	         |<- - HTTP/1.1 101 Switching Protocols - - -|
//	         |                                           |
//	         |<---------~ WebSockets Handshake ~-------->|
//	         |                                           |
//	         |------ Frame: TextMessage, "Hello" ------->|
//	         |                                           |
//	         |<------ Frame: TextMessage, "Hello" -------|
//	         |                                           |
//	         .                                           .
package websocket
