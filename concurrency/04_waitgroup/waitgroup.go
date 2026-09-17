package waitgroup

import (
	"primitives/internal/futex"
	"sync/atomic"
)

type WaitGroup struct {
	count uint32
}

func (wg *WaitGroup) Add(delta int) {
	for {
		current := atomic.LoadUint32(&wg.count)
		newValue := int64(current) + int64(delta)
		if newValue < 0 {
			panic("negative count")
		}

		if newValue > int64(^uint32(0)) {
			panic("uint32 overflow")
		}

		if atomic.CompareAndSwapUint32(&wg.count, current, uint32(newValue)) {
			if newValue == 0 {
				futex.WakeAll(&wg.count)
			}
			return
		}
	}
}

func (wg *WaitGroup) Done() {
	wg.Add(-1)
}

func (wg *WaitGroup) Wait() {
	for {
		current := atomic.LoadUint32(&wg.count)
		if current == 0 {
			return
		}
		futex.Wait(&wg.count, current)
	}
}
