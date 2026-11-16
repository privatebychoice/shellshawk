package presence

import "testing"

func TestTracker(t *testing.T) {
	tr := New(nil)
	leave1 := tr.Enter(1)
	leave2 := tr.Enter(1) // second session
	tr.Enter(2)
	if !tr.IsOnline(1) || len(tr.Online()) != 2 {
		t.Fatalf("online = %v", tr.Online())
	}
	leave1()
	leave1() // idempotent
	if !tr.IsOnline(1) {
		t.Error("member offline while a second session is open")
	}
	leave2()
	if tr.IsOnline(1) || tr.IsOnline(3) {
		t.Error("member still online after all sessions ended")
	}
}
