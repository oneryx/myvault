package app

import (
	"fmt"
	"time"

	"github.com/oneryx/myvault/cmd/myvault/core"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

// passkeyText describes a passkey without any of its secret material: its
// relying party and when it was created.
func passkeyText(f *state.Fido2Credential) string {
	site := f.RpID
	if site == "" {
		site = f.RpName
	}
	created := ""
	if t, err := time.Parse(time.RFC3339Nano, f.CreationDate); err == nil {
		created = "Created " + t.Local().Format("Jan 2, 2006")
	}
	switch {
	case site != "" && created != "":
		return site + " · " + created
	case site != "":
		return site
	case created != "":
		return created
	}
	return "Stored in this item"
}

func passkeyTestID(base string, i int) string {
	if i == 0 {
		return base
	}
	return fmt.Sprintf("%s-%d", base, i)
}

// ConfirmRemovePasskey asks before marking passkey i of the item being
// edited for removal. It goes only when the user saves.
func (m *AppModel) ConfirmRemovePasskey(cx *core.Scope, i int) {
	d := m.EditDraft.Get()
	if i < 0 || i >= len(d.DraftPasskeys()) || d.PasskeyRemoved(i) {
		return
	}
	cx.ShowAlert(core.AlertConfig{
		Title:   "Remove passkey?",
		Message: "You will no longer be able to sign in with this passkey.",
		Actions: []core.AlertAction{
			{Label: "Cancel", Role: core.AlertCancel},
			{Label: "Remove", Role: core.AlertDestructive},
		},
		Cancelable: true,
	}, func(idx int) {
		if idx == 1 {
			m.MutateDraft(func(d *EditDraft) {
				if !d.PasskeyRemoved(i) {
					d.RemovedPasskeys = append(d.RemovedPasskeys, i)
				}
			})
		}
	})
}

func hasDraftPasskeys(m *AppModel) bool {
	return len(m.EditDraft.Get().DraftPasskeys()) > 0
}
