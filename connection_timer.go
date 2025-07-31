package quic

import (
	"fmt"
	"time"

	"github.com/quic-go/quic-go/internal/utils"
)

var deadlineSendImmediately = time.Time{}.Add(42 * time.Millisecond) // any value > time.Time{} and before time.Now() is fine

type connectionTimer struct {
	timer *utils.Timer
	last  time.Time
}

func newTimer() *connectionTimer {
	return &connectionTimer{timer: utils.NewTimer()}
}

func (t *connectionTimer) SetRead() {
	if deadline := t.timer.Deadline(); deadline != deadlineSendImmediately {
		t.last = deadline
	}
	fmt.Println("ConnectionTimer SetRead")
	t.timer.SetRead()
}

func (t *connectionTimer) Chan() <-chan time.Time {
	return t.timer.Chan()
}

// SetTimer resets the timer.
// It makes sure that the deadline is strictly increasing.
// This prevents busy-looping in cases where the timer fires, but we can't actually send out a packet.
// This doesn't apply to the pacing deadline, which can be set multiple times to deadlineSendImmediately.
func (t *connectionTimer) SetTimer(idleTimeoutOrKeepAlive, connIDRetirement, ackAlarm, lossTime, pacing, defenseControlInterval time.Time) {
	deadline := idleTimeoutOrKeepAlive
	fmt.Println("ConnectionTimer idleTimeoutOrKeepAlive")
	if !connIDRetirement.IsZero() && connIDRetirement.Before(deadline) && connIDRetirement.After(t.last) {
		fmt.Println("ConnectionTimer connIDRetirement")
		deadline = connIDRetirement
	}
	if !ackAlarm.IsZero() && ackAlarm.Before(deadline) && ackAlarm.After(t.last) {
		fmt.Println("ConnectionTimer ackAlarm")
		deadline = ackAlarm
	}
	if !lossTime.IsZero() && lossTime.Before(deadline) && lossTime.After(t.last) {
		fmt.Println("ConnectionTimer lossTime")
		deadline = lossTime
	}
	if !pacing.IsZero() && pacing.Before(deadline) && pacing.After(t.last) {
		fmt.Println("ConnectionTimer pacing")
		deadline = pacing
	}
	if !defenseControlInterval.IsZero() && defenseControlInterval.Before(deadline) && defenseControlInterval.After(t.last) {
		fmt.Println("ConnectionTimer defenseControlInterval")
		deadline = defenseControlInterval
	}
	if deadline == idleTimeoutOrKeepAlive {
		fmt.Printf("defenseControlInterval deadline: %v\n", defenseControlInterval)
	}
	fmt.Printf("new deadline: %v\n", deadline)
	t.timer.Reset(deadline)
}

func (t *connectionTimer) Stop() {
	t.timer.Stop()
}
