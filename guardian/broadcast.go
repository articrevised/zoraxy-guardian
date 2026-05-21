package guardian

import "sync"

// broadcaster fan-outs BlockLogEntry events to any number of subscribers.
// Sends are non-blocking: if a subscriber's channel is full the message is
// dropped for that subscriber (the SSE client just misses a tick, fine).
type broadcaster struct {
	mu   sync.Mutex
	subs map[chan BlockLogEntry]struct{}
}

func newBroadcaster() *broadcaster {
	return &broadcaster{subs: make(map[chan BlockLogEntry]struct{})}
}

// Subscribe returns a buffered channel that will receive future events.
// The caller must call Unsubscribe when done.
func (b *broadcaster) Subscribe() chan BlockLogEntry {
	ch := make(chan BlockLogEntry, 32)
	b.mu.Lock()
	b.subs[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *broadcaster) Unsubscribe(ch chan BlockLogEntry) {
	b.mu.Lock()
	if _, ok := b.subs[ch]; ok {
		delete(b.subs, ch)
		close(ch)
	}
	b.mu.Unlock()
}

func (b *broadcaster) publish(e BlockLogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
			// Subscriber too slow; drop.
		}
	}
}
