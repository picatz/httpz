package clock

import "time"

// Face is the interface for a clock that can be used to get the current time.
//
// This is useful for testing.
type Face interface {
	// Now returns the current time.
	Now() time.Time
}

// System is the system clock.
type System struct{}

// Now returns the current time.
func (System) Now() time.Time {
	return time.Now()
}

// Mock is a mock clock.
type Mock struct {
	// Now is the current time.
	now time.Time
}

// Now returns the current time.
func (m Mock) Now() time.Time {
	return m.now
}

// SetNow sets the current time.
func (m *Mock) SetNow(now time.Time) {
	m.now = now
}
