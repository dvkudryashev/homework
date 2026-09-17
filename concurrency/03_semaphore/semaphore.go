package semaphore

import (
	"primitives/internal/futex"
	"sync/atomic"
)

type Semaphore struct {
	permits uint32
}

func New(n int) *Semaphore {
	return &Semaphore{
		permits: uint32(n),
	}
}

func (s *Semaphore) Acquire() {
	for {
		permits := atomic.LoadUint32(&s.permits)
		if permits > 0 {
			if !atomic.CompareAndSwapUint32(&s.permits, permits, permits-1) {
				continue
			}
			return
		}

		futex.Wait(&s.permits, 0)
	}
}

func (s *Semaphore) TryAcquire() bool {
	for {
		permits := atomic.LoadUint32(&s.permits)
		if permits == 0 {
			return false
		}
		if atomic.CompareAndSwapUint32(&s.permits, permits, permits-1) {
			return true
		}
	}
}

func (s *Semaphore) Release() {
	for {
		permits := atomic.LoadUint32(&s.permits)
		if !atomic.CompareAndSwapUint32(&s.permits, permits, permits+1) {
			continue
		}
		futex.Wake(&s.permits)
		return
	}
}

func (s *Semaphore) Available() int {
	return int(atomic.LoadUint32(&s.permits))
}
