package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func (m *AppModel) filterTitle() string {
	switch m.Route.Get() {
	case RouteGenerator:
		return "Generator"
	case RouteSettings:
		return "Settings"
	case RouteHealth:
		return "Vault Health"
	case RouteImport:
		return "Import"
	}
	if m.SearchIsGlobal() {
		return "All Items"
	}
	return m.sectionTitle()
}

func (m *AppModel) sectionTitle() string {
	f := m.SidebarFilter.Get()
	if f.Type != nil {
		switch *f.Type {
		case api.CipherTypeLogin:
			return "Logins"
		case api.CipherTypeCard:
			return "Cards"
		case api.CipherTypeIdentity:
			return "Identities"
		case api.CipherTypeSecureNote:
			return "Secure Notes"
		case api.CipherTypeSSHKey:
			return "SSH Keys"
		}
	}
	if f.CollectionID != "" {
		for _, col := range m.Collections.Get() {
			if col.ID == f.CollectionID {
				return col.Name
			}
		}
		return "Collection"
	}
	if f.FolderID != "" {
		for _, folder := range m.Folders.Get() {
			if folder.ID == f.FolderID {
				return folder.Name
			}
		}
		return "Folder"
	}
	switch f.Category {
	case state.FilterFavorites:
		return "Favorites"
	case state.FilterTrash:
		return "Trash"
	case state.FilterArchive:
		return "Archive"
	case state.FilterNoFolder:
		return "No Folder"
	}
	return "All Items"
}

func nonEmpty(values ...string) []string {
	var out []string
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

func cipherBrand(c *state.Cipher) string {
	if c.Card != nil {
		return c.Card.Brand
	}
	return ""
}

func maskCardNumber(num string) string {
	digits := strings.ReplaceAll(num, " ", "")
	if len(digits) <= 4 {
		return "••••"
	}
	return "•••• •••• •••• " + digits[len(digits)-4:]
}

func formatRelativeTime(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	case d < 7*24*time.Hour:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
	return t.Local().Format("Jan 2")
}

func cipherURIs(c *state.Cipher) []string {
	if c == nil || c.Login == nil {
		return nil
	}
	out := make([]string, 0, len(c.Login.URIs))
	for _, u := range c.Login.URIs {
		out = append(out, u.URI)
	}
	return out
}
