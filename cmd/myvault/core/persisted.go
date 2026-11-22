package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/egoist/mygo/ui"
)

var (
	storageMu  sync.Mutex
	storageDir string
)

// SetStorageDir sets where persisted values are kept, one JSON file each.
func SetStorageDir(dir string) {
	storageMu.Lock()
	storageDir = dir
	storageMu.Unlock()
}

type PersistOptions struct {
	Version int
}

type persistedEntry struct {
	Version int             `json:"version"`
	Value   json.RawMessage `json:"value"`
}

// Persisted is a signal saved to disk on every write.
type Persisted[T any] struct {
	sig  *Signal[T]
	path string
	opts PersistOptions
}

func NewPersisted[T any](_ *Scope, key string, def T, opts PersistOptions) *Persisted[T] {
	storageMu.Lock()
	dir := storageDir
	storageMu.Unlock()
	p := &Persisted[T]{opts: opts}
	if dir != "" {
		p.path = filepath.Join(dir, key+".json")
	}
	v := def
	if p.path != "" {
		if raw, err := os.ReadFile(p.path); err == nil {
			var e persistedEntry
			if json.Unmarshal(raw, &e) == nil && e.Version == opts.Version {
				var got T
				if json.Unmarshal(e.Value, &got) == nil {
					v = got
				}
			}
		}
	}
	p.sig = NewSignalFunc[T](nil, v, nil)
	return p
}

func (p *Persisted[T]) Get() T { return p.sig.Get() }

func (p *Persisted[T]) Set(v T) error {
	p.sig.Set(v)
	if p.path == "" {
		return nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(persistedEntry{Version: p.opts.Version, Value: data})
	if err != nil {
		return err
	}
	tmp := p.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.path)
}

func (p *Persisted[T]) Update(fn func(T) T) error { return p.Set(fn(p.sig.GetUntracked())) }

// Ref names a control so the model can focus it.
type Ref struct{ Handle ui.Handle }

// Focus asks for the keyboard focus on the control, once it shows.
func (r *Ref) Focus() { r.Handle.Focus() }
