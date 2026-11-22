package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/oneryx/myvault/cmd/myvault/core"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

// TrashDeletable counts the items in Trash the user may delete permanently.
func (m *AppModel) TrashDeletable() int {
	return len(m.Core.TrashSelection().Items)
}

func (m *AppModel) EmptyTrash(cx *core.Scope) {
	if m.LockState.Get() != state.StatusUnlocked || m.SyncState.Get() == SyncOffline || m.TrashBusy.Get() {
		return
	}
	sel := m.Core.TrashSelection()
	n := len(sel.Items)
	if n == 0 {
		return
	}
	noun := "items"
	if n == 1 {
		noun = "item"
	}
	cx.ShowAlert(core.AlertConfig{
		Title:   "Empty Trash?",
		Message: fmt.Sprintf("%d %s will be permanently deleted and cannot be recovered.", n, noun),
		Actions: []core.AlertAction{
			{Label: "Cancel", Role: core.AlertCancel},
			{Label: "Empty Trash", Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx != 1 {
			return
		}
		m.TrashBusy.Set(true)
		gen := m.LockGeneration()
		go func() {
			res, err := m.Core.EmptyTrash(context.Background(), sel)
			m.Scope.Post(func() {
				m.TrashBusy.Set(false)
				if !m.StillUnlocked(gen) {
					return
				}
				m.SelectedID.Set("")
				m.ActiveCipher.Set(nil)
				m.RefreshVaultData()
				var notes []string
				if res.ReadOnly > 0 {
					notes = append(notes, fmt.Sprintf("%d read-only item(s) stayed in Trash.", res.ReadOnly))
				}
				if res.Skipped > 0 {
					notes = append(notes, fmt.Sprintf("%d item(s) changed on another device and were kept.", res.Skipped))
				}
				desc := strings.Join(notes, " ")
				switch {
				case err != nil && res.Deleted == 0:
					m.ShowToast(ToastError, "Empty Trash failed", friendlyError(err))
				case err != nil:
					m.ShowToast(ToastWarning, fmt.Sprintf("Deleted %d item(s)", res.Deleted), "Some items could not be deleted: "+friendlyError(err))
				default:
					m.ShowToast(ToastInfo, "Trash emptied", desc)
				}
			})
		}()
	})
}

// CanClone reports whether c may be copied into a new personal item: its
// secrets must be visible to the user.
func (m *AppModel) CanClone(c *state.Cipher) bool {
	return c != nil && c.DeletedDate == nil && !m.PasswordHidden(c) && m.SyncState.Get() != SyncOffline
}

// CloneActive opens the editor on a new personal copy of the selected item.
// Organization membership, attachments and history are not copied.
func (m *AppModel) CloneActive(cx *core.Scope) {
	c := m.ActiveCipher.Get()
	if !m.CanClone(c) || m.EditMode.Get() {
		return
	}
	m.ResetIdleTimer()
	m.GateReprompt(cx, c, "clone item", func() {
		if cur := m.ActiveCipher.Get(); cur == nil || cur.ID != c.ID {
			return
		}
		src := *c
		src.ID = ""
		src.OrganizationID = nil
		src.CollectionIDs = nil
		src.Attachments = nil
		src.PasswordHistory = nil
		src.RevisionDate = nil
		src.CreationDate = nil
		src.DeletedDate = nil
		src.ArchivedDate = nil
		src.Key = nil
		src.Data = nil
		src.EncryptedFor = nil
		src.EncryptedByKeyID = nil
		src.ReadOnly = false
		src.HidePassword = false
		src.Name = c.Name + " (Copy)"
		// A passkey belongs to one item; Bitwarden does not copy it either.
		hadPasskey := false
		if c.Login != nil {
			login := *c.Login
			hadPasskey = len(login.Fido2Credentials) > 0
			login.Fido2Credentials = nil
			src.Login = &login
		}
		draft := draftFromCipher(&src)
		draft.IsNew = true
		draft.Revision = nil
		m.openDraft(draft)
		m.EditDirty.Set(true)
		m.EditError.Set("")
		m.EditMode.Set(true)
		if hadPasskey {
			m.ShowToast(ToastInfo, "Passkeys are not copied", "The copy has the login details without the passkey.")
		}
	})
}
