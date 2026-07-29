package protocol

import (
	"context"
	"sync"
	"testing"
	"time"
)

func newTestHandler(t *testing.T) (*Handler, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	return NewHandler(ctx, HandlerConfig{}, nil), cancel
}

// TestDeliverResponseNeverBlocks verifies that a flood of duplicate responses
// for a single request never parks the delivering goroutines and that exactly
// one value is handed to the waiter. With a blocking send every duplicate past
// the first would leak a goroutine.
func TestDeliverResponseNeverBlocks(t *testing.T) {
	h, cancel := newTestHandler(t)
	defer cancel()

	req := h.addPendingRequest([]byte("reqhash"), nil, PingPacket)

	const dups = 200
	var wg sync.WaitGroup
	wg.Add(dups)
	for i := 0; i < dups; i++ {
		go func() {
			defer wg.Done()
			h.deliverResponse(req, "pong")
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("deliverResponse blocked: delivering goroutines leaked")
	}

	// Exactly one value is buffered for the waiter, the rest were dropped.
	select {
	case <-req.ResponseChan:
	default:
		t.Fatal("expected one delivered response")
	}
	select {
	case <-req.ResponseChan:
		t.Fatal("more than one response buffered")
	default:
	}
}

// TestDuplicateResponsesWaiterGetsOneNoLeak mirrors the real flow: a waiter
// consumes one response and removes the request while duplicate responses race
// through getPendingRequest and deliverResponse. The waiter must receive
// exactly one response and every delivery goroutine must finish.
func TestDuplicateResponsesWaiterGetsOneNoLeak(t *testing.T) {
	h, cancel := newTestHandler(t)
	defer cancel()

	hash := []byte("reqhash")
	req := h.addPendingRequest(hash, nil, PingPacket)

	got := make(chan interface{}, 1)
	var waiter sync.WaitGroup
	waiter.Add(1)
	go func() {
		defer waiter.Done()
		resp := <-req.ResponseChan
		h.removePendingRequest(string(hash))
		got <- resp
	}()

	const dups = 200
	var wg sync.WaitGroup
	wg.Add(dups)
	for i := 0; i < dups; i++ {
		go func() {
			defer wg.Done()
			if r := h.getPendingRequest(string(hash)); r != nil {
				h.deliverResponse(r, "pong")
			}
		}()
	}

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("duplicate responses leaked delivering goroutines")
	}

	waiter.Wait()
	select {
	case <-got:
	default:
		t.Fatal("waiter did not receive a response")
	}
}
