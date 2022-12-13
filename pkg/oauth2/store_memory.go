package oauth2

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/exp/slog"

	"github.com/picatz/httpz/pkg/clock"
)

// StoreMemory is an in-memory store used to persist items
// of the given type to a persistent storage backend.
type StoreMemory[T any] struct {
	// contains filtered or unexported fields
	sync.RWMutex

	// Items stored in memory.
	data map[string]T

	// TTL is the time to live for items stored in the store.
	TTL time.Duration

	// Clock is the clock used to determine the current time.
	Clock clock.Face

	// Logger is the logger used to log messages.
	Logger *slog.Logger
}

// New returns a new memory store for the given type.
func NewStoreMemory[T any]() *StoreMemory[T] {
	var t T
	return &StoreMemory[T]{
		data:   make(map[string]T),
		TTL:    0,
		Clock:  clock.System{},
		Logger: slog.Default().WithGroup(fmt.Sprintf("oauth2/store/memory/%T", t)),
	}
}

// Get returns the item with the given key.
func (s *StoreMemory[T]) Get(key string) (*T, error) {
	s.RLock()
	defer s.RUnlock()

	item, ok := s.data[key]
	if !ok {
		return nil, fmt.Errorf("item with key %q not found", key)
	}

	return &item, nil
}

// Set sets the item with the given key.
func (s *StoreMemory[T]) Set(key string, item T) error {
	s.Lock()
	defer s.Unlock()

	s.data[key] = item

	return nil
}

// Delete deletes the item with the given key.
func (s *StoreMemory[T]) Delete(key string) error {
	s.Lock()
	defer s.Unlock()

	delete(s.data, key)

	return nil
}

// List returns all items in the store.
func (s *StoreMemory[T]) List(filter Filter[T]) ([]T, error) {
	s.RLock()
	defer s.RUnlock()

	items := make([]T, 0, len(s.data))
	for _, item := range s.data {
		// Apply filter.
		if filter != nil && !filter(&item) {
			continue
		}
		items = append(items, item)
	}

	return items, nil
}

// Close closes the store.
func (s *StoreMemory[T]) Close() error {
	return nil
}
