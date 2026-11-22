package app

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func solidPNG(t *testing.T, size int) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for i := range img.Pix {
		img.Pix[i] = 0xff
	}
	data, err := encodePNG(img)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func bmpEntry(size int) []byte {
	var b bytes.Buffer
	header := make([]byte, 40)
	binary.LittleEndian.PutUint32(header[0:], 40)
	binary.LittleEndian.PutUint32(header[4:], uint32(size))
	binary.LittleEndian.PutUint32(header[8:], uint32(size*2))
	binary.LittleEndian.PutUint16(header[12:], 1)
	binary.LittleEndian.PutUint16(header[14:], 32)
	b.Write(header)
	for range size * size {
		b.Write([]byte{0x10, 0x20, 0x30, 0xff})
	}
	b.Write(make([]byte, (size+31)/32*4*size))
	return b.Bytes()
}

func buildICO(entries ...[]byte) []byte {
	sizes := []int{16, 48, 32}
	var out bytes.Buffer
	_ = binary.Write(&out, binary.LittleEndian, [3]uint16{0, 1, uint16(len(entries))})
	offset := 6 + 16*len(entries)
	for i, e := range entries {
		dir := make([]byte, 16)
		dir[0], dir[1] = byte(sizes[i]), byte(sizes[i])
		binary.LittleEndian.PutUint16(dir[4:], 1)
		binary.LittleEndian.PutUint16(dir[6:], 32)
		binary.LittleEndian.PutUint32(dir[8:], uint32(len(e)))
		binary.LittleEndian.PutUint32(dir[12:], uint32(offset))
		out.Write(dir)
		offset += len(e)
	}
	for _, e := range entries {
		out.Write(e)
	}
	return out.Bytes()
}

func decodedSize(t *testing.T, data []byte) int {
	t.Helper()
	if !bytes.HasPrefix(data, pngSignature) {
		t.Fatalf("not a PNG: % x", data[:min(8, len(data))])
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	return img.Bounds().Dx()
}

func TestNormalizeIconPicksLargestStaticFrame(t *testing.T) {
	ico := buildICO(solidPNG(t, 16), solidPNG(t, 48), solidPNG(t, 32))
	got, err := normalizeIcon(ico)
	if err != nil || decodedSize(t, got) != 48 {
		t.Fatalf("multi-entry PNG .ico = (%d bytes, %v)", len(got), err)
	}

	bmp, err := normalizeIcon(buildICO(bmpEntry(16), bmpEntry(48)))
	if err != nil || decodedSize(t, bmp) != 48 {
		t.Fatalf("BMP .ico = (%d bytes, %v)", len(bmp), err)
	}
	img, _ := png.Decode(bytes.NewReader(bmp))
	if c := color.NRGBAModel.Convert(img.At(3, 3)).(color.NRGBA); c != (color.NRGBA{R: 0x30, G: 0x20, B: 0x10, A: 0xff}) {
		t.Fatalf("BMP pixel = %+v", c)
	}

	plain := solidPNG(t, 32)
	if same, err := normalizeIcon(plain); err != nil || !bytes.Equal(same, plain) {
		t.Fatal("single-frame PNG was re-encoded")
	}
}

func TestFaviconStoreNormalizesCachedICO(t *testing.T) {
	dir := t.TempDir()
	s := NewFaviconStore(FaviconStoreConfig{CacheDir: dir})
	s.SetAccount("acct-1")
	path := s.diskPath("login.live.com")
	if err := os.WriteFile(path, buildICO(solidPNG(t, 16), solidPNG(t, 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := s.load(faviconJob{domain: "login.live.com", generation: s.generation})
	if err != nil || decodedSize(t, data) != 32 {
		t.Fatalf("load = (%d bytes, %v)", len(data), err)
	}
	if onDisk, _ := os.ReadFile(filepath.Clean(path)); !bytes.Equal(onDisk, data) {
		t.Fatal("cached .ico was not rewritten as PNG")
	}
}
