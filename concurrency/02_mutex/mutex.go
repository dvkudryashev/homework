package mutex

import (
	"primitives/internal/futex"
	"sync/atomic"
)

const (
	free = iota
	held
	contended
)

type Mutex struct {
	state uint32
}

func (m *Mutex) Lock() {
	if atomic.CompareAndSwapUint32(&m.state, free, held) {
		return
	}

	for {
		switch atomic.LoadUint32(&m.state) {
		case free:
			if atomic.CompareAndSwapUint32(&m.state, free, contended) {
				return
			}
		case held:
			if atomic.CompareAndSwapUint32(&m.state, held, contended) {
			}
		case contended:
			for range 10 {
				if atomic.LoadUint32(&m.state) == free {
					if !atomic.CompareAndSwapUint32(&m.state, free, contended) {
						continue
					}
					return
				}
			}
			futex.Wait(&m.state, contended)
		}
	}
}

func (m *Mutex) TryLock() bool {
	return atomic.CompareAndSwapUint32(&m.state, free, held)
}

func (m *Mutex) Unlock() {
	switch atomic.SwapUint32(&m.state, free) {
	case free:
		panic("tried to unlock free mutex")
	case held:
		return
	case contended:
		futex.Wake(&m.state)
	}
}
