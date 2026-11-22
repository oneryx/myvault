package app

import (
	"sync"

	"github.com/egoist/mygo/ui"
	"github.com/oneryx/myvault/internal/vaultcore/api"
)

// iconBitmaps keeps the decoded site icons, by their data.
var iconBitmaps = struct {
	sync.Mutex
	m map[*byte]*ui.Bitmap
}{m: map[*byte]*ui.Bitmap{}}

func iconBitmap(data []byte) *ui.Bitmap {
	if len(data) == 0 {
		return nil
	}
	iconBitmaps.Lock()
	defer iconBitmaps.Unlock()
	key := &data[0]
	if bm, ok := iconBitmaps.m[key]; ok {
		return bm
	}
	bm, err := ui.DecodeBitmap(data)
	if err != nil {
		bm = nil
	}
	if len(iconBitmaps.m) > 2000 {
		clear(iconBitmaps.m)
	}
	iconBitmaps.m[key] = bm
	return bm
}

// siteEmblem shows the site's icon of a login, or its colored emblem.
func siteEmblem(c *ui.Context, m *AppModel, uris []string, name string, t api.CipherType, brand string, size float32) {
	if bm := iconBitmap(m.SiteIcon(uris)); bm != nil {
		faviconTile(c, bm, size)
		return
	}
	itemEmblem(c, name, t, brand, size)
}

func faviconTile(c *ui.Context, bm *ui.Bitmap, size float32) {
	inner := size * 0.68
	ui.Box(c).Size(size, size).Shrink(0).Radius(size*0.26).Center().Background(rgb(0xffffff)).
		Shadow(0, 0, 0, 0.5, rgba(0x000000, 0.12)).Children(func() {
		ui.Image(c, bm).Size(inner, inner).Fit(ui.Contain).Radius(size * 0.08)
	})
}
