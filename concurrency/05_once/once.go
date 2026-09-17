package once

import (
	"primitives/internal/futex"
	"sync/atomic"
)

type Once struct {
	state uint32
}

const (
	idle = iota
	running
	done
)

func (o *Once) Do(f func()) {
	for {
		switch atomic.LoadUint32(&o.state) {
		case idle:
			if atomic.CompareAndSwapUint32(&o.state, idle, running) {
				defer func() {
					atomic.StoreUint32(&o.state, done)
					futex.WakeAll(&o.state)
				}()
				f()
				return
			}
		case running:
			futex.Wait(&o.state, running)
		case done:
			return
		}
	}
}

func (o *Once) Done() bool {
	return atomic.LoadUint32(&o.state) == done
}
