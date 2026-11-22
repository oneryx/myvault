// Package core is a small reactive layer: signals, memos and effects that
// re-run when what they read changes. The app model keeps its state in
// signals; every write asks the window to draw a new frame, and the views,
// which mygo builds every frame, read the signals directly.
//
// Signals are written on the main thread. Get is safe from any goroutine.
package core

import (
	"sync"
)

type computation struct {
	fn       func()
	deps     map[*source]struct{}
	disposed bool
	queued   bool
}

// source is what a computation can depend on.
type source struct {
	subs map[*computation]struct{}
}

var rt struct {
	mu      sync.Mutex
	current *computation
	batch   int
	queue   []*computation
	flush   bool
}

// invalidate asks the windows for a new frame. The app sets it.
var invalidate func()

// SetInvalidate sets the function every signal write calls.
func SetInvalidate(fn func()) { invalidate = fn }

func (s *source) track() {
	rt.mu.Lock()
	c := rt.current
	if c != nil && !c.disposed {
		if s.subs == nil {
			s.subs = map[*computation]struct{}{}
		}
		s.subs[c] = struct{}{}
		if c.deps == nil {
			c.deps = map[*source]struct{}{}
		}
		c.deps[s] = struct{}{}
	}
	rt.mu.Unlock()
}

func (s *source) notify() {
	rt.mu.Lock()
	for c := range s.subs {
		if !c.queued && !c.disposed {
			c.queued = true
			rt.queue = append(rt.queue, c)
		}
	}
	run := rt.batch == 0 && !rt.flush
	rt.mu.Unlock()
	if invalidate != nil {
		invalidate()
	}
	if run {
		flush()
	}
}

func flush() {
	rt.mu.Lock()
	if rt.flush {
		rt.mu.Unlock()
		return
	}
	rt.flush = true
	rt.mu.Unlock()
	for i := 0; ; i++ {
		rt.mu.Lock()
		if len(rt.queue) == 0 || i > 10000 {
			rt.queue = nil
			rt.flush = false
			rt.mu.Unlock()
			return
		}
		c := rt.queue[0]
		rt.queue = rt.queue[1:]
		c.queued = false
		rt.mu.Unlock()
		c.run()
	}
}

func (c *computation) unlink() {
	for s := range c.deps {
		delete(s.subs, c)
	}
	c.deps = nil
}

func (c *computation) run() {
	rt.mu.Lock()
	if c.disposed {
		rt.mu.Unlock()
		return
	}
	c.unlink()
	prev := rt.current
	rt.current = c
	rt.mu.Unlock()
	defer func() {
		rt.mu.Lock()
		rt.current = prev
		rt.mu.Unlock()
	}()
	c.fn()
}

func (c *computation) dispose() {
	rt.mu.Lock()
	c.disposed = true
	c.unlink()
	rt.mu.Unlock()
}

func untrack(fn func()) {
	rt.mu.Lock()
	prev := rt.current
	rt.current = nil
	rt.mu.Unlock()
	defer func() {
		rt.mu.Lock()
		rt.current = prev
		rt.mu.Unlock()
	}()
	fn()
}

func batch(fn func()) {
	rt.mu.Lock()
	rt.batch++
	rt.mu.Unlock()
	defer func() {
		rt.mu.Lock()
		rt.batch--
		run := rt.batch == 0 && !rt.flush
		rt.mu.Unlock()
		if run {
			flush()
		}
	}()
	fn()
}

// Signal holds a value that effects and memos follow.
type Signal[T any] struct {
	src   source
	mu    sync.RWMutex
	v     T
	equal func(a, b T) bool
}

func looseEqual[T any](a, b T) (eq bool) {
	defer func() {
		if recover() != nil {
			eq = false
		}
	}()
	return any(a) == any(b)
}

// NewSignal makes a signal whose writes of an equal value change nothing.
func NewSignal[T any](_ *Scope, v T) *Signal[T] {
	return &Signal[T]{v: v, equal: looseEqual[T]}
}

// NewSignalFunc makes a signal compared with equal; nil makes every write a
// change.
func NewSignalFunc[T any](_ *Scope, v T, equal func(a, b T) bool) *Signal[T] {
	return &Signal[T]{v: v, equal: equal}
}

func (s *Signal[T]) Get() T {
	s.src.track()
	return s.GetUntracked()
}

func (s *Signal[T]) GetUntracked() T {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v
}

func (s *Signal[T]) Set(v T) {
	s.mu.Lock()
	if s.equal != nil && s.equal(s.v, v) {
		s.mu.Unlock()
		return
	}
	s.v = v
	s.mu.Unlock()
	s.src.notify()
}

func (s *Signal[T]) Update(fn func(T) T) { s.Set(fn(s.GetUntracked())) }

// Memo is a value computed from signals, kept until they change.
type Memo[T any] struct{ sig *Signal[T] }

func NewMemo[T any](cx *Scope, fn func() T) *Memo[T] {
	m := &Memo[T]{sig: &Signal[T]{equal: looseEqual[T]}}
	c := &computation{}
	c.fn = func() { m.sig.Set(fn()) }
	c.run()
	cx.own(c)
	return m
}

func (m *Memo[T]) Get() T { return m.sig.Get() }

// NewSelector returns a function reporting whether source equals a key.
func NewSelector[K comparable](_ *Scope, source func() K) func(K) bool {
	return func(k K) bool { return source() == k }
}

// Untracked reads fn without following what it reads.
func Untracked[T any](_ *Scope, fn func() T) (v T) {
	untrack(func() { v = fn() })
	return v
}

// Collection is an ordered list of items with keys.
type Collection[K comparable, T any] struct {
	sig *Signal[[]T]
	key func(T) K
}

func NewCollectionFunc[K comparable, T any](_ *Scope, key func(T) K, _ func(a, b T) bool, items []T) *Collection[K, T] {
	return &Collection[K, T]{sig: &Signal[[]T]{v: items}, key: key}
}

func (c *Collection[K, T]) Len() int          { return len(c.sig.Get()) }
func (c *Collection[K, T]) KeyAt(i int) K     { return c.key(c.sig.Get()[i]) }
func (c *Collection[K, T]) Items() []T        { return c.sig.Get() }
func (c *Collection[K, T]) Replace(items []T) { c.sig.Set(items) }
func (c *Collection[K, T]) At(i int) (T, bool) {
	items := c.sig.Get()
	if i < 0 || i >= len(items) {
		var zero T
		return zero, false
	}
	return items[i], true
}
