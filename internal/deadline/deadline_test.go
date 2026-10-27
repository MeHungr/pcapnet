package deadline

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestPastDeadlineIsImmediate(t *testing.T) {
	var d Deadline
	d.Set(time.Now().Add(-time.Second))
	ctx, finish := d.Begin(context.Background())
	defer finish()
	if !errors.Is(context.Cause(ctx), os.ErrDeadlineExceeded) {
		t.Fatal("expired deadline was not applied synchronously")
	}
}

func TestDeadlineChangesAndCancellation(t *testing.T) {
	var d Deadline
	ctx, finish := d.Begin(context.Background())
	defer finish()
	// Updates must reach an operation already blocked with no deadline.
	d.Set(time.Now().Add(time.Hour))
	d.Set(time.Now().Add(-time.Second))
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), os.ErrDeadlineExceeded) {
			t.Fatal(context.Cause(ctx))
		}
	case <-time.After(time.Second):
		t.Fatal("deadline change did not wake operation")
	}
	parent, cancel := context.WithCancel(context.Background())
	var other Deadline
	operation, join := other.Begin(parent)
	cancel()
	join()
	if !errors.Is(context.Cause(operation), context.Canceled) {
		t.Fatal(context.Cause(operation))
	}
}

func TestTimerRechecksExtendedDeadline(t *testing.T) {
	calls := 0
	future := time.Now().Add(time.Hour)
	changed := make(chan struct{})
	// The third snapshot occurs after the first timer fires. Extending here
	// reproduces the stale-timer race without depending on goroutine scheduling.
	ctx, finish := Context(context.Background(), func() (time.Time, <-chan struct{}) {
		calls++
		if calls <= 2 {
			return time.Now().Add(time.Millisecond), changed
		}
		return future, changed
	})
	defer finish()
	select {
	case <-ctx.Done():
		t.Fatalf("stale timer canceled extended deadline: %v", context.Cause(ctx))
	case <-time.After(15 * time.Millisecond):
	}
}
