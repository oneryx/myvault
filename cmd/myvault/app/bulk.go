package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/oneryx/myvault/cmd/myvault/core"
	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

// bulkSet is what each action may change among several chosen items:
// items the user cannot edit are skipped where writing needs edit rights.
type bulkSet struct {
	all                                       []*state.Cipher
	movable, trashable, restorable, deletable []*state.Cipher
	archivable, unarchivable                  []*state.Cipher
	inTrash                                   bool
}

func (m *AppModel) bulkSelection(ids []string) bulkSet {
	var b bulkSet
	canArchive := m.Core.CanArchive()
	for _, id := range ids {
		c, err := m.Core.GetCipher(id)
		if err != nil {
			continue
		}
		b.all = append(b.all, c)
		ro := m.CipherReadOnly(c)
		switch {
		case c.DeletedDate != nil:
			b.inTrash = true
			if !ro {
				b.restorable = append(b.restorable, c)
				b.deletable = append(b.deletable, c)
			}
		default:
			b.movable = append(b.movable, c)
			if !ro {
				b.trashable = append(b.trashable, c)
			}
			if c.ArchivedDate == nil && canArchive {
				b.archivable = append(b.archivable, c)
			} else if c.ArchivedDate != nil {
				b.unarchivable = append(b.unarchivable, c)
			}
		}
	}
	return b
}

// bulkWritable reports whether several items may be changed now: online
// and with no other such action running.
func (m *AppModel) bulkWritable() bool {
	return m.SyncState.Get() != SyncOffline && !m.BulkBusy.Get()
}

// itemCount is "1 item" or "n items".
func itemCount(n int) string {
	if n == 1 {
		return "1 item"
	}
	return fmt.Sprintf("%d items", n)
}

// skippedNote tells how many chosen items an action leaves alone.
func skippedNote(n int) string {
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(" %s you cannot edit will be skipped.", itemCount(n))
}

// MoveToFolder files the items ids in the folder folderID, "" for No
// Folder, in one request. Items in Trash or there already are left alone.
func (m *AppModel) MoveToFolder(ids []string, folderID string) {
	if !m.bulkWritable() {
		return
	}
	var todo []string
	for _, c := range m.bulkSelection(ids).movable {
		if !inFolder(c, folderID) {
			todo = append(todo, c.ID)
		}
	}
	if len(todo) == 0 {
		return
	}
	where := "No Folder"
	var dest *string
	if folderID != "" {
		dest = &folderID
		for _, f := range m.Folders.Get() {
			if f.ID == folderID {
				where = f.Name
			}
		}
	}
	m.dispatchBulk(func(ctx context.Context) bulkOutcome {
		if err := m.Core.MoveCiphers(ctx, todo, dest); err != nil {
			return bulkOutcome{err: err}
		}
		return bulkOutcome{done: len(todo)}
	}, func(out bulkOutcome) {
		if out.err != nil {
			m.ShowToast(ToastError, "Move stopped", "Some items may have moved. "+friendlyError(out.err))
			return
		}
		m.ShowToast(ToastSuccess, fmt.Sprintf("Moved %s to %s", itemCount(out.done), where), "")
	}, false)
}

func inFolder(c *state.Cipher, folderID string) bool {
	if c.FolderID == nil || *c.FolderID == "" {
		return folderID == ""
	}
	return *c.FolderID == folderID
}

// TrashItems asks before moving the chosen items to Trash.
func (m *AppModel) TrashItems(cx *core.Scope, ids []string) {
	b := m.bulkSelection(ids)
	if b.inTrash || len(b.trashable) == 0 || !m.bulkWritable() {
		return
	}
	items := b.trashable
	cx.ShowAlert(core.AlertConfig{
		Title:   fmt.Sprintf("Move %s to Trash?", itemCount(len(items))),
		Message: "Items in Trash can be restored." + skippedNote(len(b.all)-len(items)),
		Actions: []core.AlertAction{
			{Label: "Cancel", Role: core.AlertCancel},
			{Label: "Move to Trash", Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx != 1 {
			return
		}
		m.runBulk(items, "Moved %s to Trash", func(ctx context.Context, c *state.Cipher) error {
			return m.Core.SoftDeleteCipher(ctx, c.ID)
		})
	})
}

// RestoreItems brings the chosen items back from Trash.
func (m *AppModel) RestoreItems(ids []string) {
	if b := m.bulkSelection(ids); len(b.restorable) > 0 && m.bulkWritable() {
		m.runBulk(b.restorable, "Restored %s", func(ctx context.Context, c *state.Cipher) error {
			return m.Core.RestoreCipher(ctx, c.ID)
		})
	}
}

// ArchiveItems moves the chosen items to the Archive, or back with archive
// false. When any of them is protected by a master password reprompt, the
// password is asked once, for the whole action.
func (m *AppModel) ArchiveItems(cx *core.Scope, ids []string, archive bool) {
	b := m.bulkSelection(ids)
	items, label, done := b.archivable, "archive items", "Archived %s"
	if !archive {
		items, label, done = b.unarchivable, "unarchive items", "Unarchived %s"
	}
	if len(items) == 0 || !m.bulkWritable() {
		return
	}
	run := func() {
		m.runBulk(items, done, func(ctx context.Context, c *state.Cipher) error {
			if archive {
				return m.Core.ArchiveCipher(ctx, c.ID)
			}
			return m.Core.UnarchiveCipher(ctx, c.ID)
		})
	}
	for _, c := range items {
		if c.Reprompt == 1 {
			m.GateReprompt(cx, c, label, run)
			return
		}
	}
	run()
}

// DeleteItemsPermanently asks before deleting the chosen items in Trash for
// good. It goes through Empty Trash, which keeps any item that changed
// since the confirmation opened.
func (m *AppModel) DeleteItemsPermanently(cx *core.Scope, ids []string) {
	b := m.bulkSelection(ids)
	if len(b.deletable) == 0 || !m.bulkWritable() {
		return
	}
	want := map[string]bool{}
	for _, c := range b.deletable {
		want[c.ID] = true
	}
	sel := m.Core.TrashSelection()
	sel.ReadOnly = 0
	var confirmed []state.TrashItem
	for _, it := range sel.Items {
		if want[it.ID] {
			confirmed = append(confirmed, it)
		}
	}
	sel.Items = confirmed
	if len(confirmed) == 0 {
		return
	}
	cx.ShowAlert(core.AlertConfig{
		Title:   fmt.Sprintf("Delete %s permanently?", itemCount(len(confirmed))),
		Message: "They cannot be recovered." + skippedNote(len(b.all)-len(confirmed)),
		Actions: []core.AlertAction{
			{Label: "Cancel", Role: core.AlertCancel},
			{Label: "Delete Permanently", Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx != 1 {
			return
		}
		m.dispatchBulk(func(ctx context.Context) bulkOutcome {
			res, err := m.Core.EmptyTrash(ctx, sel)
			return bulkOutcome{done: res.Deleted, kept: res.Skipped, err: err}
		}, func(out bulkOutcome) {
			m.showBulkResult("Deleted %s", out)
		}, true)
	})
}

// bulkOutcome is what an action on several items did.
type bulkOutcome struct {
	done   int
	failed []bulkFailure
	// kept counts items Empty Trash kept as they changed meanwhile.
	kept int
	// err stopped the action.
	err   error
	local bool
}

type bulkFailure struct {
	name string
	err  error
}

// stopsBulk reports a failure that every further item would meet too.
func stopsBulk(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, state.ErrLocked) || errors.Is(err, api.ErrNetworkOffline) ||
		errors.Is(err, api.ErrUnauthorized) || errors.Is(err, state.ErrArchiveUnsupported)
}

// runBulk applies do to each item in turn and reports once, with done
// worded like "Moved %s to Trash". A lost session or connection stops it.
func (m *AppModel) runBulk(items []*state.Cipher, done string, do func(context.Context, *state.Cipher) error) {
	m.dispatchBulk(func(ctx context.Context) bulkOutcome {
		var out bulkOutcome
		for _, c := range items {
			err := do(ctx, c)
			var lc *state.LocalCopyError
			switch {
			case err == nil:
				out.done++
			case errors.As(err, &lc):
				out.done++
				out.local = true
			default:
				out.failed = append(out.failed, bulkFailure{c.Name, err})
				if stopsBulk(ctx, err) {
					return out
				}
			}
		}
		return out
	}, func(out bulkOutcome) { m.showBulkResult(done, out) }, true)
}

// dispatchBulk runs work in the session, then refreshes the vault, clears
// the list's choice when clear is set, and reports through show.
func (m *AppModel) dispatchBulk(work func(context.Context) bulkOutcome, show func(bulkOutcome), clear bool) {
	ctx, cancel, err := m.Core.SessionContext(context.Background())
	if err != nil {
		return
	}
	gen := m.LockGeneration()
	m.BulkBusy.Set(true)
	go func() {
		defer cancel()
		out := work(ctx)
		m.Scope.Post(func() {
			m.BulkBusy.Set(false)
			if !m.StillUnlocked(gen) {
				return
			}
			if clear {
				clearListSelection()
				m.SelectedID.Set("")
				m.ActiveCipher.Set(nil)
			}
			m.RefreshVaultData()
			show(out)
		})
	}()
}

func (m *AppModel) showBulkResult(done string, out bulkOutcome) {
	title := fmt.Sprintf(done, itemCount(out.done))
	var notDone []string
	for _, f := range out.failed {
		notDone = append(notDone, fmt.Sprintf("%s: %s", f.name, friendlyError(f.err)))
	}
	if out.kept > 0 {
		notDone = append(notDone, fmt.Sprintf("%s changed on another device and were kept", itemCount(out.kept)))
	}
	switch {
	case out.err != nil:
		m.ShowToast(ToastError, title, friendlyError(out.err))
	case len(notDone) > 0:
		m.ShowToast(ToastError, title, fmt.Sprintf("Not done (%d): %s", len(notDone), joinShort(notDone)))
	case out.local:
		m.ShowLocalCopyWarning(title)
	default:
		m.ShowToast(ToastSuccess, title, "")
	}
}

// joinShort lists up to three reasons and counts the rest.
func joinShort(s []string) string {
	if len(s) <= 3 {
		return strings.Join(s, "; ")
	}
	return fmt.Sprintf("%s; and %d more", strings.Join(s[:3], "; "), len(s)-3)
}
