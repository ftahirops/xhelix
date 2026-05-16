package main

import "sync"

// liveHubT is a simple fanout for live-stream events
// (alerts/spawns/connects). Subscribers get their own bounded
// channel; publishers drop on full channel so a slow client can
// never back-pressure the detection path.
type liveHubT struct {
	mu   sync.Mutex
	subs map[chan map[string]any]struct{}
}

func newLiveHub() *liveHubT {
	return &liveHubT{subs: map[chan map[string]any]struct{}{}}
}

func (h *liveHubT) subscribe(buf int) chan map[string]any {
	if buf <= 0 {
		buf = 32
	}
	ch := make(chan map[string]any, buf)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *liveHubT) unsubscribe(ch chan map[string]any) {
	h.mu.Lock()
	if _, ok := h.subs[ch]; ok {
		delete(h.subs, ch)
		close(ch)
	}
	h.mu.Unlock()
}

// publish fans out to every subscriber. Non-blocking: a slow
// subscriber drops events rather than stalling the producer.
func (h *liveHubT) publish(ev map[string]any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- ev:
		default:
		}
	}
}
