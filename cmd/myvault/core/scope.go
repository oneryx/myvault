package core

import (
	"io"
	"os"
	"sync"
)

// Scope owns effects and cleanups, and reaches the platform: posting work
// to the main thread, alerts, biometrics and the clipboard.
type Scope struct {
	host *Host

	mu       sync.Mutex
	comps    []*computation
	cleanups []func()
	disposed bool
}

// Host is what the app provides to scopes.
type Host struct {
	// Post runs fn on the main thread later. It must not block.
	Post func(fn func())
	// SetClipboard writes plain text to the clipboard.
	SetClipboard func(text string)
	// BiometricAvailability reports what the device can authenticate with.
	BiometricAvailability func() BiometricKind
	// AuthenticateBiometric asks the user to authenticate; done gets the
	// result on any goroutine.
	AuthenticateBiometric func(reason string, done func(BiometricResult))
	// PickFiles shows an open dialog; it may block.
	PickFiles func(opts PickFilesOptions) ([]File, error)

	alertMu sync.Mutex
	alerts  []*PendingAlert
}

// NewScope makes the app's root scope.
func NewScope(h *Host) *Scope { return &Scope{host: h} }

func (cx *Scope) Host() *Host { return cx.host }

// Child makes a scope that Dispose of cx also disposes.
func (cx *Scope) Child() *Scope {
	child := &Scope{host: cx.host}
	cx.Cleanup(child.Dispose)
	return child
}

func (cx *Scope) own(c *computation) {
	cx.mu.Lock()
	cx.comps = append(cx.comps, c)
	cx.mu.Unlock()
}

// Post runs fn on the main thread later, in one batch, unless cx is
// disposed by then. It is safe from any goroutine.
func (cx *Scope) Post(fn func()) {
	if cx.host == nil || cx.host.Post == nil {
		batch(fn)
		return
	}
	cx.host.Post(func() {
		cx.mu.Lock()
		dead := cx.disposed
		cx.mu.Unlock()
		if !dead {
			batch(fn)
		}
	})
}

// Effect runs fn now and again whenever what it read changes.
func (cx *Scope) Effect(fn func()) (stop func()) {
	c := &computation{fn: fn}
	cx.own(c)
	rt.mu.Lock()
	deferred := rt.batch > 0 || rt.flush
	if deferred {
		c.queued = true
		rt.queue = append(rt.queue, c)
	}
	rt.mu.Unlock()
	if !deferred {
		c.run()
	}
	return c.dispose
}

func (cx *Scope) Untrack(fn func()) { untrack(fn) }

// Batch runs fn, then the effects its writes scheduled, once each.
func (cx *Scope) Batch(fn func()) { batch(fn) }

func (cx *Scope) Cleanup(fn func()) {
	cx.mu.Lock()
	cx.cleanups = append(cx.cleanups, fn)
	cx.mu.Unlock()
}

// Dispose stops the scope's effects and runs its cleanups, last first.
func (cx *Scope) Dispose() {
	cx.mu.Lock()
	if cx.disposed {
		cx.mu.Unlock()
		return
	}
	cx.disposed = true
	comps, cleanups := cx.comps, cx.cleanups
	cx.comps, cx.cleanups = nil, nil
	cx.mu.Unlock()
	for _, c := range comps {
		c.dispose()
	}
	for i := len(cleanups) - 1; i >= 0; i-- {
		cleanups[i]()
	}
}

func (cx *Scope) SetClipboard(text string) {
	if cx.host != nil && cx.host.SetClipboard != nil {
		cx.host.SetClipboard(text)
	}
}

// BiometricAvailability reports what the device authenticates with, to fn
// on the main thread.
func (cx *Scope) BiometricAvailability(fn func(BiometricKind)) {
	if cx.host == nil || cx.host.BiometricAvailability == nil {
		fn(BiometricNone)
		return
	}
	go func() {
		kind := cx.host.BiometricAvailability()
		cx.Post(func() { fn(kind) })
	}()
}

// AuthenticateBiometric asks the user to authenticate, then runs done on
// the main thread with the result.
func (cx *Scope) AuthenticateBiometric(reason string, done func(BiometricResult)) {
	if cx.host == nil || cx.host.AuthenticateBiometric == nil {
		done(BiometricUnavailable)
		return
	}
	cx.host.AuthenticateBiometric(reason, func(res BiometricResult) {
		cx.Post(func() { done(res) })
	})
}

// BiometricKind is what the device authenticates its owner with.
type BiometricKind int

const (
	BiometricNone BiometricKind = iota
	BiometricFingerprint
	BiometricFace
)

// BiometricResult is the outcome of AuthenticateBiometric.
type BiometricResult int

const (
	BiometricSuccess BiometricResult = iota
	BiometricCancelled
	BiometricFailed
	BiometricUnavailable
)

// AlertRole is what a button of an alert does.
type AlertRole int

const (
	AlertDefault AlertRole = iota
	AlertCancel
	AlertDestructive
)

type AlertAction struct {
	Label string
	Role  AlertRole
}

type AlertConfig struct {
	Title      string
	Message    string
	Actions    []AlertAction
	Cancelable bool
}

// PendingAlert is an alert waiting for the user's answer.
type PendingAlert struct {
	Config AlertConfig
	Open   bool
	done   func(int)
}

// ShowAlert queues an alert; done gets the index of the action chosen, or
// -1 when the alert was dismissed.
func (cx *Scope) ShowAlert(cfg AlertConfig, done func(int)) {
	h := cx.host
	if h == nil {
		return
	}
	h.alertMu.Lock()
	h.alerts = append(h.alerts, &PendingAlert{Config: cfg, Open: true, done: done})
	h.alertMu.Unlock()
	if invalidate != nil {
		invalidate()
	}
}

// Alert returns the alert to show, or nil.
func (h *Host) Alert() *PendingAlert {
	h.alertMu.Lock()
	defer h.alertMu.Unlock()
	if len(h.alerts) == 0 {
		return nil
	}
	return h.alerts[0]
}

// Answer closes the alert shown with the action chosen, -1 for none.
func (h *Host) Answer(a *PendingAlert, idx int) {
	h.alertMu.Lock()
	if len(h.alerts) > 0 && h.alerts[0] == a {
		h.alerts = h.alerts[1:]
	}
	h.alertMu.Unlock()
	if a.done != nil {
		batch(func() { a.done(idx) })
	}
	if invalidate != nil {
		invalidate()
	}
}

// ClearAlerts drops every alert, unanswered.
func (h *Host) ClearAlerts() {
	h.alertMu.Lock()
	h.alerts = nil
	h.alertMu.Unlock()
}

// File is a file the user picked.
type File struct {
	Name string
	Path string
	Size int64
	// Temporary files are removed by whoever reads them.
	Temporary bool
}

// Open opens the file for reading.
func (f File) Open() (io.ReadCloser, error) { return os.Open(f.Path) }

type PickFilesOptions struct {
	Title  string
	Button string
	// Types are extensions such as ".json".
	Types []string
}

// PickFiles asks the user for a file, then runs done on the main thread.
func (cx *Scope) PickFiles(opts PickFilesOptions, done func([]File, error)) {
	if cx.host == nil || cx.host.PickFiles == nil {
		done(nil, nil)
		return
	}
	go func() {
		files, err := cx.host.PickFiles(opts)
		cx.Post(func() { done(files, err) })
	}()
}
