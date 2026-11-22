package app

import (
	"sync"
	"time"

	"github.com/egoist/mygo/ui"
)

// ToastType is the kind of a toast, which its look tells.
type ToastType string

const (
	ToastInfo    ToastType = "info"
	ToastSuccess ToastType = "success"
	ToastWarning ToastType = "warning"
	ToastError   ToastType = "error"
)

// ToastContent is a toast the model asks for.
type ToastContent struct {
	Type        ToastType
	Title       string
	Description string
	Duration    time.Duration
	Action      string
	OnAction    func()
}

// Toaster queues the model's toasts until the window's view shows them.
type Toaster struct {
	mu      sync.Mutex
	pending []ToastContent
}

func (t *Toaster) Show(c ToastContent) {
	t.mu.Lock()
	t.pending = append(t.pending, c)
	t.mu.Unlock()
}

// Pending returns the toasts queued since the last call.
func (t *Toaster) Pending() []ToastContent {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.pending
	t.pending = nil
	return p
}

// Flush shows the queued toasts in the window being built.
func (t *Toaster) Flush(c *ui.Context) {
	for _, p := range t.Pending() {
		c.AddToast(ui.Toast{
			ID:          p.Title,
			Title:       p.Title,
			Description: p.Description,
			Type:        string(p.Type),
			Timeout:     p.Duration,
			Action:      p.Action,
			OnAction:    p.OnAction,
		})
	}
}
