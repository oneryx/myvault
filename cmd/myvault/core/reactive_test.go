package core

import (
	"path/filepath"
	"testing"
)

func TestSignalSkipsEqualWrites(t *testing.T) {
	cx := NewScope(nil)
	defer cx.Dispose()
	s := NewSignal(cx, 1)
	runs := 0
	cx.Effect(func() { s.Get(); runs++ })
	s.Set(1)
	if runs != 1 {
		t.Fatalf("an equal write ran the effect: %d runs", runs)
	}
	s.Set(2)
	if runs != 2 || s.Get() != 2 {
		t.Fatalf("after a change: %d runs, value %d", runs, s.Get())
	}

	always := NewSignalFunc[[]int](cx, nil, nil)
	n := 0
	cx.Effect(func() { always.Get(); n++ })
	always.Set(nil)
	if n != 2 {
		t.Fatalf("a signal without equal skipped a write: %d runs", n)
	}
}

func TestEffectFollowsOnlyWhatItReadLast(t *testing.T) {
	cx := NewScope(nil)
	defer cx.Dispose()
	which, a, b := NewSignal(cx, true), NewSignal(cx, 0), NewSignal(cx, 0)
	runs := 0
	cx.Effect(func() {
		runs++
		if which.Get() {
			a.Get()
		} else {
			b.Get()
		}
	})
	which.Set(false)
	a.Set(1)
	if runs != 2 {
		t.Fatalf("a signal no longer read ran the effect: %d runs", runs)
	}
	b.Set(1)
	if runs != 3 {
		t.Fatalf("the signal read now did not run the effect: %d runs", runs)
	}
	stop := cx.Effect(func() { cx.Untrack(func() { a.Get() }); runs++ })
	a.Set(2)
	if runs != 4 {
		t.Fatalf("an untracked read ran the effect: %d runs", runs)
	}
	stop()
}

func TestBatchRunsEffectsOnceAfter(t *testing.T) {
	cx := NewScope(nil)
	defer cx.Dispose()
	a, b := NewSignal(cx, 0), NewSignal(cx, 0)
	var seen [][2]int
	cx.Effect(func() { seen = append(seen, [2]int{a.Get(), b.Get()}) })
	cx.Batch(func() {
		a.Set(1)
		b.Set(2)
		if len(seen) != 1 {
			t.Fatal("an effect ran inside the batch")
		}
	})
	if len(seen) != 2 || seen[1] != [2]int{1, 2} {
		t.Fatalf("effect runs = %v, want one run seeing both writes", seen)
	}
}

func TestMemoAndDispose(t *testing.T) {
	cx := NewScope(nil)
	s := NewSignal(cx, 2)
	double := NewMemo(cx, func() int { return s.Get() * 2 })
	runs := 0
	cx.Effect(func() { double.Get(); runs++ })
	s.Set(3)
	if double.Get() != 6 || runs != 2 {
		t.Fatalf("memo = %d after %d runs", double.Get(), runs)
	}
	cleaned := false
	cx.Cleanup(func() { cleaned = true })
	cx.Dispose()
	s.Set(4)
	if !cleaned || runs != 2 {
		t.Fatalf("after Dispose: cleaned %v, runs %d", cleaned, runs)
	}
}

func TestPostRunsOnTheHostInABatch(t *testing.T) {
	var queue []func()
	cx := NewScope(&Host{Post: func(fn func()) { queue = append(queue, fn) }})
	a, b := NewSignal(cx, 0), NewSignal(cx, 0)
	runs := 0
	cx.Effect(func() { a.Get(); b.Get(); runs++ })
	cx.Post(func() { a.Set(1); b.Set(1) })
	if runs != 1 || len(queue) != 1 {
		t.Fatal("Post ran at once")
	}
	queue[0]()
	if runs != 2 {
		t.Fatalf("a posted function ran effects %d times, want once", runs-1)
	}
	cx.Dispose()
	cx.Post(func() { a.Set(2) })
	queue[1]()
	if a.Get() != 1 {
		t.Fatal("a function posted to a disposed scope ran")
	}
}

func TestAlertsAnswerInOrder(t *testing.T) {
	h := &Host{}
	cx := NewScope(h)
	var got []int
	cx.ShowAlert(AlertConfig{Title: "first"}, func(i int) { got = append(got, i) })
	cx.ShowAlert(AlertConfig{Title: "second"}, func(i int) { got = append(got, 10+i) })
	first := h.Alert()
	if first == nil || first.Config.Title != "first" {
		t.Fatalf("first alert = %+v", first)
	}
	h.Answer(first, 1)
	h.Answer(h.Alert(), -1)
	if h.Alert() != nil || len(got) != 2 || got[0] != 1 || got[1] != 9 {
		t.Fatalf("answers = %v", got)
	}
}

func TestPersistedRoundTrip(t *testing.T) {
	dir := t.TempDir()
	SetStorageDir(dir)
	defer SetStorageDir("")
	type prefs struct{ N int }
	p := NewPersisted(nil, "prefs", prefs{N: 1}, PersistOptions{Version: 1})
	if p.Get().N != 1 {
		t.Fatal("default not used")
	}
	if err := p.Update(func(v prefs) prefs { v.N = 7; return v }); err != nil {
		t.Fatal(err)
	}
	if again := NewPersisted(nil, "prefs", prefs{}, PersistOptions{Version: 1}); again.Get().N != 7 {
		t.Fatalf("reloaded %+v", again.Get())
	}
	if other := NewPersisted(nil, "prefs", prefs{N: 3}, PersistOptions{Version: 2}); other.Get().N != 3 {
		t.Fatal("a value of another version was read")
	}
	if tmp, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(tmp) != 0 {
		t.Fatalf("a write left %v", tmp)
	}
}
