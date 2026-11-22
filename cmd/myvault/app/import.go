package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/egoist/mygo/ui"
	"github.com/oneryx/myvault/cmd/myvault/core"
	"github.com/oneryx/myvault/internal/vaultcore/crypto"
	"github.com/oneryx/myvault/internal/vaultcore/export"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

type BackupMode int

const (
	BackupNone BackupMode = iota
	BackupExport
	BackupImport
)

const minBackupPasswordLength = 8

// ImportSession is a decrypted backup under review. It holds secrets, so
// it lives only until the import is applied, cancelled or the vault locks.
type ImportSession struct {
	FileName string
	Plan     *export.Plan
}

// importPending is a picked backup file waiting for its password.
type importPending struct {
	name string
	data []byte
}

func (m *AppModel) clearBackupState() {
	m.backupOp++
	m.BackupDialog.Set(BackupNone)
	m.BackupPW.Set("")
	m.BackupPW2.Set("")
	m.BackupError.Set("")
	m.BackupBusy.Set(false)
	if m.importPending != nil {
		crypto.ZeroBytes(m.importPending.data)
		m.importPending = nil
	}
	m.ImportSession.Set(nil)
	m.ImportBusy.Set(false)
	m.ImportShowIdentical.Set(false)
}

// StartExport asks for the master password, then for a backup password.
func (m *AppModel) StartExport() {
	if m.LockState.Get() != state.StatusUnlocked {
		return
	}
	m.ResetIdleTimer()
	gen := m.LockGeneration()
	m.openRepromptDialog("export your vault", func() {
		if m.StillUnlocked(gen) {
			m.openBackupDialog(BackupExport)
		}
	})
}

func (m *AppModel) openBackupDialog(mode BackupMode) {
	m.BackupPW.Set("")
	m.BackupPW2.Set("")
	m.BackupError.Set("")
	m.BackupBusy.Set(false)
	m.BackupDialog.Set(mode)
}

func (m *AppModel) CloseBackupDialog() {
	m.backupOp++
	if m.BackupDialog.Get() == BackupImport && m.importPending != nil {
		crypto.ZeroBytes(m.importPending.data)
		m.importPending = nil
	}
	m.BackupDialog.Set(BackupNone)
	m.BackupPW.Set("")
	m.BackupPW2.Set("")
	m.BackupError.Set("")
	m.BackupBusy.Set(false)
}

func (m *AppModel) ConfirmBackupDialog(cx *core.Scope) {
	if m.BackupBusy.Get() {
		return
	}
	switch m.BackupDialog.Get() {
	case BackupExport:
		m.confirmExport(cx)
	case BackupImport:
		m.confirmImportPassword()
	}
}

func (m *AppModel) confirmExport(cx *core.Scope) {
	pw := m.BackupPW.Get()
	switch {
	case len([]rune(pw)) < minBackupPasswordLength:
		m.BackupError.Set(fmt.Sprintf("Use at least %d characters.", minBackupPasswordLength))
		return
	case pw != m.BackupPW2.Get():
		m.BackupError.Set("The passwords do not match.")
		return
	}
	backup := m.Core.BackupData()
	if n := len(backup.Unreadable); n > 0 {
		m.BackupError.Set(fmt.Sprintf("%d personal item(s) are in a format MyVault cannot read, so the backup would be incomplete. Export from the Bitwarden web vault instead.", n))
		return
	}
	m.BackupBusy.Set(true)
	m.BackupError.Set("")
	gen := m.LockGeneration()
	pwBytes := []byte(pw)
	ciphers, folders := backup.Ciphers, backup.Folders
	go func() {
		defer crypto.ZeroBytes(pwBytes)
		var data []byte
		v, err := export.Build(ciphers, folders)
		if err == nil {
			data, err = export.EncryptWithPassword(v, pwBytes, export.DefaultKDF)
		}
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) {
				crypto.ZeroBytes(data)
				return
			}
			m.BackupBusy.Set(false)
			if err != nil {
				m.BackupError.Set(err.Error())
				return
			}
			m.CloseBackupDialog()
			name := "myvault_encrypted_export_" + time.Now().Format("20060102150405") + ".json"
			m.chooseSavePath(cx, name, func(target saveTarget, err error) {
				if err != nil || target.dir == "" || !m.StillUnlocked(gen) {
					crypto.ZeroBytes(data)
					if err != nil {
						m.ShowToast(ToastError, "Export failed", err.Error())
					}
					return
				}
				go func() {
					_, published, err := m.savePrivateFile(gen, target, data)
					m.Scope.Post(func() {
						switch {
						case err != nil:
							m.ShowToast(ToastError, "Export failed", err.Error())
						case published:
							m.ShowToast(ToastSuccess, "Encrypted backup saved", "Keep the backup password safe; it cannot be recovered.")
						}
					})
				}()
			})
		})
	}()
}

// StartImport picks a Bitwarden JSON export. Nothing in the vault changes
// until the user approves items in the review.
func (m *AppModel) StartImport(cx *core.Scope) {
	if m.LockState.Get() != state.StatusUnlocked {
		return
	}
	m.ResetIdleTimer()
	gen := m.LockGeneration()
	cx.PickFiles(core.PickFilesOptions{Title: "Import Backup", Button: "Import", Types: []string{".json"}}, func(files []core.File, err error) {
		if err != nil {
			m.ShowToast(ToastError, "Could not open file", err.Error())
			return
		}
		if len(files) == 0 {
			return
		}
		f := files[0]
		go func() {
			data, err := readBackupFile(f)
			m.Scope.Post(func() {
				if !m.StillUnlocked(gen) {
					crypto.ZeroBytes(data)
					return
				}
				if err != nil {
					m.ShowToast(ToastError, "Import failed", err.Error())
					return
				}
				m.receiveBackup(f.Name, data)
			})
		}()
	})
}

func readBackupFile(f core.File) ([]byte, error) {
	if f.Temporary && f.Path != "" {
		defer os.Remove(f.Path)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, export.MaxFileSize+1))
	if err != nil {
		crypto.ZeroBytes(data)
		return nil, err
	}
	if len(data) > export.MaxFileSize {
		crypto.ZeroBytes(data)
		return nil, fmt.Errorf("the file is larger than %d MiB", export.MaxFileSize>>20)
	}
	return data, nil
}

func (m *AppModel) receiveBackup(name string, data []byte) {
	needs, err := export.NeedsPassword(data)
	if err != nil {
		crypto.ZeroBytes(data)
		m.ShowToast(ToastError, "Import failed", backupError(err))
		return
	}
	if needs {
		m.importPending = &importPending{name: name, data: data}
		m.openBackupDialog(BackupImport)
		return
	}
	v, err := export.Read(data, nil)
	crypto.ZeroBytes(data)
	if err != nil {
		m.ShowToast(ToastError, "Import failed", backupError(err))
		return
	}
	m.beginImportReview(name, v)
}

func (m *AppModel) confirmImportPassword() {
	pending := m.importPending
	pw := m.BackupPW.Get()
	if pending == nil || pw == "" {
		m.BackupError.Set("Enter the backup password.")
		return
	}
	m.BackupBusy.Set(true)
	m.BackupError.Set("")
	gen := m.LockGeneration()
	m.backupOp++
	op := m.backupOp
	pwBytes := []byte(pw)
	// The worker reads its own copy: Cancel and lock zero pending.data.
	data := bytes.Clone(pending.data)
	go func() {
		defer crypto.ZeroBytes(pwBytes)
		defer crypto.ZeroBytes(data)
		v, err := export.Read(data, pwBytes)
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) || op != m.backupOp || m.importPending != pending {
				return
			}
			m.BackupBusy.Set(false)
			if errors.Is(err, export.ErrWrongPassword) {
				m.BackupError.Set("Incorrect backup password.")
				return
			}
			m.CloseBackupDialog()
			if err != nil {
				m.ShowToast(ToastError, "Import failed", backupError(err))
				return
			}
			m.beginImportReview(pending.name, v)
		})
	}()
}

func backupError(err error) string {
	switch {
	case errors.Is(err, export.ErrNotBitwardenExport):
		return "This is not a Bitwarden JSON export."
	case errors.Is(err, export.ErrAccountRestricted):
		return "This backup is locked to its account. Export it again as a password-protected file."
	}
	return friendlyError(err)
}

func (m *AppModel) beginImportReview(name string, v *export.Vault) {
	current := m.Core.AllCiphers()
	for _, c := range current {
		c.ReadOnly = c.ReadOnly || m.CipherReadOnly(c)
		c.HidePassword = c.HidePassword || m.PasswordHidden(c)
	}
	plan := export.BuildPlan(v, current, m.Core.Folders())
	m.ImportShowIdentical.Set(false)
	m.ImportSession.Set(&ImportSession{FileName: name, Plan: plan})
	m.Route.Set(RouteImport)
}

// mutateImport changes the plan and redraws the review.
func (m *AppModel) mutateImport(fn func(p *export.Plan)) {
	sess := m.ImportSession.Get()
	if sess == nil || m.ImportBusy.Get() {
		return
	}
	m.ResetIdleTimer()
	fn(sess.Plan)
	m.ImportRev.Set(m.ImportRev.GetUntracked() + 1)
}

func (m *AppModel) SetImportAction(i int, a export.Action) {
	sess := m.ImportSession.Get()
	if sess == nil || i < 0 || i >= len(sess.Plan.Entries) {
		return
	}
	if e := &sess.Plan.Entries[i]; a == export.ActionUpdate && e.NeedsReprompt() && slices.Contains(e.Allowed(), a) {
		gen := m.LockGeneration()
		m.openRepromptDialog("update a protected item", func() {
			if m.StillUnlocked(gen) && m.ImportSession.Get() == sess {
				m.mutateImport(func(*export.Plan) {
					e.ApproveReprompt()
					e.SetAction(a)
				})
			}
		})
		m.ImportRev.Set(m.ImportRev.GetUntracked() + 1)
		return
	}
	m.mutateImport(func(p *export.Plan) { p.Entries[i].SetAction(a) })
}

// BatchImport sets action a on every entry of class, where allowed.
func (m *AppModel) BatchImport(class export.Class, a export.Action) {
	m.mutateImport(func(p *export.Plan) {
		for i := range p.Entries {
			if p.Entries[i].Class == class {
				p.Entries[i].SetAction(a)
			}
		}
	})
}

func (m *AppModel) SkipAllImport() {
	m.mutateImport(func(p *export.Plan) {
		for i := range p.Entries {
			p.Entries[i].SetAction(export.ActionSkip)
		}
	})
}

func (m *AppModel) CancelImport() {
	if m.ImportBusy.Get() {
		return
	}
	m.ImportSession.Set(nil)
	m.Route.Set(RouteVault)
}

func (m *AppModel) ApplyImport() {
	sess := m.ImportSession.Get()
	if sess == nil || m.ImportBusy.Get() || m.SyncState.Get() == SyncOffline {
		return
	}
	if c := sess.Plan.Counts(); c.Create+c.Update == 0 {
		return
	}
	ctx, cancel, err := m.Core.SessionContext(context.Background())
	if err != nil {
		return
	}
	m.ImportBusy.Set(true)
	gen := m.LockGeneration()
	go func() {
		defer cancel()
		res := export.Apply(ctx, m.Core, sess.Plan)
		m.Scope.Post(func() {
			if !m.StillUnlocked(gen) {
				return
			}
			m.ImportBusy.Set(false)
			m.ImportSession.Set(nil)
			m.Route.Set(RouteVault)
			m.RefreshVaultData()
			title := fmt.Sprintf("Imported: %d created, %d updated", res.Created, res.Updated)
			if res.LocalCopyErr != nil && res.Failed == 0 {
				m.ShowLocalCopyWarning(title)
				return
			}
			if res.Failed > 0 {
				m.ShowToast(ToastWarning, title, fmt.Sprintf("%d item(s) failed: %s", res.Failed, friendlyError(res.Err)))
				return
			}
			m.ShowToast(ToastSuccess, title, fmt.Sprintf("%d skipped", res.Skipped))
		})
	}()
}

func importActionLabel(e *export.Entry, a export.Action) string {
	switch a {
	case export.ActionCreate:
		if e.Class == export.ClassNew {
			return "Create"
		}
		return "Create Copy"
	case export.ActionUpdate:
		return "Update Existing"
	}
	return "Skip"
}

// importDestination names where a matched vault item lives: the personal
// vault, or an organization and its collections.
func (m *AppModel) importDestination(c *state.Cipher) string {
	if c == nil || c.OrganizationID == nil || *c.OrganizationID == "" {
		return "your personal vault"
	}
	org := "an organization"
	for _, o := range m.Core.Organizations() {
		if o.ID == *c.OrganizationID {
			org = o.Name
		}
	}
	var cols []string
	for _, col := range m.Core.Collections() {
		if slices.Contains(c.CollectionIDs, col.ID) {
			cols = append(cols, col.Name)
		}
	}
	if len(cols) == 0 {
		return "the shared vault of " + org
	}
	return org + " · " + strings.Join(cols, ", ")
}

func identicalToggleLabel(shown bool, n int) string {
	if shown {
		return fmt.Sprintf("Hide %d identical items", n)
	}
	return fmt.Sprintf("Show %d identical items", n)
}

// ImportView reviews a backup before anything in the vault changes.
func ImportView(c *ui.Context, m *AppModel) {
	p := pal(c)
	sess := m.ImportSession.Get()
	ui.Column(c).Grow(1).FillWidth().Background(p.Canvas).Children(func() {
		if sess == nil {
			ui.Column(c).Grow(1).Center().Gap(8).Children(func() {
				ui.Text(c, "No Import in Progress").FontSize(13).FontWeight(600).TextColor(p.Fg)
				ui.Text(c, "Choose Import Backup in Settings to review a backup.").FontSize(12).TextColor(p.Fg2)
			})
			return
		}
		pageImportReview(c, m, sess)
	})
}

func pageImportReview(c *ui.Context, m *AppModel, sess *ImportSession) {
	p := pal(c)
	m.ImportRev.Get()
	plan := sess.Plan
	counts := plan.Counts()
	busy := m.ImportBusy.Get()
	pageScroll(c, 760, 16, func() {
		ui.Column(c).Gap(4).Children(func() {
			ui.Text(c, "Review Import").FontSize(17).FontWeight(600).TextColor(p.Fg)
			ui.Text(c, fmt.Sprintf("%s · %d new, %d changed, %d identical. Nothing changes until you apply.", sess.FileName, counts.New, counts.Conflicts, counts.Identical)).
				FontSize(12.5).TextColor(p.Fg2)
		})
		ui.Row(c).Wrap().Gap(8).Children(func() {
			batch := func(text string, run func()) { ui.Button(c, text).FontSize(12).OnClick(run) }
			batch("Select All New", func() { m.BatchImport(export.ClassNew, export.ActionCreate) })
			batch("Skip All Conflicts", func() { m.BatchImport(export.ClassConflict, export.ActionSkip) })
			batch("Copy All Conflicts", func() { m.BatchImport(export.ClassConflict, export.ActionCreate) })
			batch("Update All Conflicts", func() { m.BatchImport(export.ClassConflict, export.ActionUpdate) })
			batch("Skip All", m.SkipAllImport)
		})
		group := func(class export.Class, title string) {
			var rows []func()
			for i := range plan.Entries {
				if plan.Entries[i].Class == class {
					rows = append(rows, func() { pageImportRow(c, m, plan, i) })
				}
			}
			if len(rows) > 0 {
				section(c, fmt.Sprintf("%s (%d)", title, len(rows)), func() { card(c, rows...) })
			}
		}
		group(export.ClassConflict, "Changed")
		group(export.ClassNew, "New")
		if counts.Identical > 0 {
			shown := m.ImportShowIdentical.Get()
			ui.Row(c).Children(func() {
				b := ui.ButtonBase(c).Height(26).Padding(0, 10).Radius(6)
				if b.Hovered() {
					b.Background(p.Fill)
				}
				b.OnClick(func() { m.ImportShowIdentical.Set(!shown) }).Children(func() {
					ui.Text(c, identicalToggleLabel(shown, counts.Identical)).FontSize(12.5).FontWeight(500).TextColor(p.Accent)
				})
			})
			if shown {
				group(export.ClassIdentical, "Identical")
			}
		}
	})
	ui.Row(c).Justify(ui.End).Gap(8).Padding(0, 28).Height(56).FillWidth().
		Background(p.List).BorderWidth(1, 0, 0, 0).BorderColor(p.Line).Children(func() {
		ui.Button(c, "Cancel").Disabled(busy).OnClick(m.CancelImport)
		ui.PrimaryButton(c, "").Disabled(busy || counts.Create+counts.Update == 0 || m.SyncState.Get() == SyncOffline).
			OnClick(m.ApplyImport).Children(func() {
			if busy {
				ui.Spinner(c).Size(12, 12)
			} else {
				ui.Icon(c, iconCheck).Size(13, 13)
			}
			ui.Text(c, fmt.Sprintf("Apply: %d create, %d update, %d skipped", counts.Create, counts.Update, counts.Skip)).SingleLine()
		})
	})
}

func pageImportRow(c *ui.Context, m *AppModel, plan *export.Plan, i int) {
	p := pal(c)
	e := &plan.Entries[i]
	sub := CipherTypeLabel(e.Item.Type)
	if e.Item.Login != nil && e.Item.Login.Username != nil && *e.Item.Login.Username != "" {
		sub = *e.Item.Login.Username
	}
	if e.FolderName != "" {
		sub += " · " + e.FolderName
	}
	var note string
	switch e.Class {
	case export.ClassConflict:
		note = "Differs: " + strings.Join(e.Diff, ", ") + " · in " + m.importDestination(e.Match)
		switch {
		case e.UpdateBlocked != "":
			note += " · cannot update: " + e.UpdateBlocked
		case !e.CanUpdate:
			note += " · existing item is read-only"
		case e.NeedsReprompt():
			note += " · protected: Update asks for your master password"
		}
	case export.ClassIdentical:
		note = "Already in " + m.importDestination(e.Match)
	case export.ClassNew:
		switch {
		case e.Unsupported:
			note = "MyVault cannot save this type of item yet, so it is skipped."
		case e.Ambiguous:
			note = "Several vault items have this name, so it is not matched to any. Choose Create to add it as a new item."
		case e.Item.ArchivedDate != nil && !m.Core.CanArchive():
			note = "Archived in the backup; it is created in your vault, since Archive needs a premium membership."
		}
	}
	ui.Row(c.Key(i)).Gap(12).Padding(8, 12, 8, 14).MinHeight(52).Children(func() {
		itemEmblem(c, e.Item.Name, e.Item.Type, "", 28)
		ui.Column(c).Grow(1).Shrink(1).Gap(2).Clip().Children(func() {
			ui.Text(c, e.Item.Name).FontSize(13.5).TextColor(p.Fg).SingleLine()
			ui.Text(c, sub).FontSize(11.5).TextColor(p.Fg3).SingleLine()
			if note != "" {
				ui.Text(c, note).FontSize(11.5).TextColor(p.Warn).MaxLines(2)
			}
		})
		allowed := e.Allowed()
		labels := make([]string, len(allowed))
		sel := ""
		for j, a := range allowed {
			labels[j] = importActionLabel(e, a)
			if a == e.Action {
				sel = labels[j]
			}
		}
		if ui.Select(c.Key("action"), &sel, labels).Label("Action for " + e.Item.Name).Width(150).Changed() {
			for j, l := range labels {
				if l == sel {
					m.SetImportAction(i, allowed[j])
				}
			}
		}
	})
}
