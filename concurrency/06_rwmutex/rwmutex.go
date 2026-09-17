package rwmutex

import (
	"primitives/internal/futex"
	"sync/atomic"
)

const (
	free   = 0
	writer = 1 << 31
)

type RWMutex struct {
	state uint32
}

func (rw *RWMutex) RLock() {
	for {
		currentState := atomic.LoadUint32(&rw.state)
		if currentState != writer {
			if currentState == writer-1 {
				panic("reader count overflow")
			}
			if atomic.CompareAndSwapUint32(&rw.state, currentState, currentState+1) {
				return
			}
		}
		futex.Wait(&rw.state, writer)
	}
}

func (rw *RWMutex) RUnlock() {
	for {
		currentState := atomic.LoadUint32(&rw.state)
		switch {
		case currentState == free:
			panic("tried to unlock unlocked")
		case currentState == writer:
			panic("tried to unlock writer's lock")
		case currentState > 0 && currentState < writer:
			if currentState > 1 {
				if atomic.CompareAndSwapUint32(&rw.state, currentState, currentState-1) {
					return
				}
			}
			if currentState == 1 {
				if atomic.CompareAndSwapUint32(&rw.state, currentState, currentState-1) {
					futex.WakeAll(&rw.state)
					return
				}
			}
		}
	}
}

func (rw *RWMutex) Lock() {
	for {
		currentState := atomic.LoadUint32(&rw.state)
		if currentState == free {
			if atomic.CompareAndSwapUint32(&rw.state, free, writer) {
				return
			}
			continue
		}
		futex.Wait(&rw.state, currentState)
	}
}

func (rw *RWMutex) Unlock() {
	if atomic.CompareAndSwapUint32(&rw.state, writer, free) {
		futex.WakeAll(&rw.state)
		return
	}
	panic("tried to unlock non-writer's lock")
}
