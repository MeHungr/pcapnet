// Package queue releases buffered references after a queue's producers stop.
package queue

// Drain discards currently queued values without blocking. Callers must first
// stop and join producers; concurrent consumers are safe. Channels stay open so
// late operations observe cancellation rather than receiving zero-value data.
func Drain[T any](ch <-chan T) {
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return
			}
		default:
			return
		}
	}
}
