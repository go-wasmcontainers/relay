// SPDX-License-Identifier: BSD-3-Clause

package relay

import (
	"context"
	"errors"
	"sync"
)

// Pipe returns the two ends of an in-memory message transport, for tests
// and for an engine running in the same process as the relay.
func Pipe() (Transport, Transport) {
	ab := make(chan []byte, 1024)
	ba := make(chan []byte, 1024)
	done := make(chan struct{})
	var once sync.Once
	closeFn := func() { once.Do(func() { close(done) }) }
	return &pipeEnd{in: ba, out: ab, done: done, close: closeFn}, &pipeEnd{in: ab, out: ba, done: done, close: closeFn}
}

type pipeEnd struct {
	in, out chan []byte
	done    chan struct{}
	close   func()
}

// ErrPipeClosed is returned once either end closed.
var ErrPipeClosed = errors.New("pipe closed")

func (p *pipeEnd) ReadMessage(ctx context.Context) ([]byte, error) {
	select {
	case m := <-p.in:
		return m, nil
	case <-p.done:
		// Drain what was sent before the close.
		select {
		case m := <-p.in:
			return m, nil
		default:
		}
		return nil, ErrPipeClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *pipeEnd) WriteMessage(ctx context.Context, m []byte) error {
	b := append([]byte(nil), m...)
	select {
	case <-p.done:
		return ErrPipeClosed
	default:
	}
	select {
	case p.out <- b:
		return nil
	case <-p.done:
		return ErrPipeClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *pipeEnd) Close(string) error {
	p.close()
	return nil
}
