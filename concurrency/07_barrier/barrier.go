package barrier

import (
	"primitives/internal/futex"
	"sync/atomic"
)

type Barrier struct {
	need    uint32
	arrived uint32
	round   uint32
}

func New(n int) *Barrier {
	return &Barrier{
		need:    uint32(n),
		arrived: 0,
		round:   0,
	}
}

func (b *Barrier) Wait() {
	currentRound := atomic.LoadUint32(&b.round)
	newArrived := atomic.AddUint32(&b.arrived, 1)

	if newArrived == b.need {
		atomic.StoreUint32(&b.arrived, 0)
		atomic.AddUint32(&b.round, 1)
		futex.WakeAll(&b.round)
		return
	}

	for {
		if atomic.LoadUint32(&b.round) != currentRound {
			return
		}
		futex.Wait(&b.round, currentRound)
	}
}
