package db

import (
	"context"
	"testing"
	"time"
)

// Every SQLite :memory: connection is its own empty database, so a second
// pooled connection would not see the migrated schema.
func TestInMemorySingleConnection(t *testing.T) {
	database := testDB(t)

	if got := database.ReaderDb.Stats().MaxOpenConnections; got != 1 {
		t.Fatalf("MaxOpenConnections = %d, want 1", got)
	}

	held, err := database.ReaderDb.Conn(context.Background())
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	errs := make(chan error, 1)
	go func() {
		_, err := database.CountNodes(LayerEL)
		errs <- err
	}()
	time.Sleep(50 * time.Millisecond)
	held.Close()

	select {
	case err := <-errs:
		if err != nil {
			t.Fatalf("count with a held connection: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("count did not finish after the held connection was released")
	}
}
