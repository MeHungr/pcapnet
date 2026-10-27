// Package deadline translates mutable network deadlines into operation contexts.
package deadline

import (
	"context"
	"os"
	"sync"
	"time"
)

// Context watches a deadline snapshot until finish is called. snapshot must
// return the current deadline and a channel closed when that deadline changes.
// finish cancels and joins the watcher, releasing its timer and goroutine.
func Context(parent context.Context, snapshot func() (time.Time, <-chan struct{})) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(parent)
	at, _ := snapshot()
	if !at.IsZero() && !time.Now().Before(at) {
		cancel(os.ErrDeadlineExceeded)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if ctx.Err() != nil {
				return
			}
			at, changed := snapshot()
			if !at.IsZero() && !time.Now().Before(at) {
				cancel(os.ErrDeadlineExceeded)
				return
			}
			var timer *time.Timer
			var timeout <-chan time.Time
			if !at.IsZero() {
				timer = time.NewTimer(time.Until(at))
				timeout = timer.C
			}
			select {
			case <-ctx.Done():
				if timer != nil {
					timer.Stop()
				}
				return
			case <-changed:
				if timer != nil {
					timer.Stop()
				}
			case <-timeout:
				// A deadline may have been extended at the same instant as the timer.
				// Always read the current value before deciding that it has expired.
			}
		}
	}()
	return ctx, func() { cancel(context.Canceled); <-done }
}

// Deadline stores a mutable timestamp. Its zero value has no deadline.
type Deadline struct {
	mu      sync.Mutex
	at      time.Time
	changed chan struct{}
}

func (d *Deadline) Set(at time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.at = at
	if d.changed != nil {
		close(d.changed)
	}
	d.changed = make(chan struct{})
}
func (d *Deadline) snapshot() (time.Time, <-chan struct{}) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.changed == nil {
		d.changed = make(chan struct{})
	}
	return d.at, d.changed
}

// Begin creates an operation context governed by this mutable deadline.
func (d *Deadline) Begin(parent context.Context) (context.Context, func()) {
	return Context(parent, d.snapshot)
}
