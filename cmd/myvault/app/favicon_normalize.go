package app

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"image/gif"
	"image/png"
	"slices"
)

var errBadIcon = errors.New("favicon: unsupported icon data")

var pngSignature = []byte("\x89PNG\r\n\x1a\n")

func isICO(b []byte) bool { return bytes.HasPrefix(b, []byte("\x00\x00\x01\x00")) }

func isGIF(b []byte) bool {
	return bytes.HasPrefix(b, []byte("GIF87a")) || bytes.HasPrefix(b, []byte("GIF89a"))
}

// needsNormalizing reports whether the image system would treat b as several
// frames: an .ico holds one image per size and a GIF may be animated, and
// both play like an animation in an image view.
func needsNormalizing(b []byte) bool { return isICO(b) || isGIF(b) }

// normalizeIcon returns b as a single static image: the best entry of an
// .ico or the first frame of a GIF, as PNG. Other formats are returned as is.
func normalizeIcon(b []byte) ([]byte, error) {
	switch {
	case isICO(b):
		return icoToPNG(b)
	case isGIF(b):
		img, err := gif.Decode(bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		return encodePNG(img)
	}
	return b, nil
}

func encodePNG(img image.Image) ([]byte, error) {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type icoEntry struct {
	size, bpp int
	data      []byte
}

func icoToPNG(b []byte) ([]byte, error) {
	if len(b) < 6 {
		return nil, errBadIcon
	}
	count := int(binary.LittleEndian.Uint16(b[4:6]))
	if count == 0 || len(b) < 6+16*count {
		return nil, errBadIcon
	}
	entries := make([]icoEntry, 0, count)
	for i := range count {
		e := b[6+16*i : 6+16*(i+1)]
		size := int(e[0])
		if size == 0 {
			size = 256
		}
		length := int(binary.LittleEndian.Uint32(e[8:12]))
		offset := int(binary.LittleEndian.Uint32(e[12:16]))
		if offset < 0 || length <= 0 || offset > len(b) || length > len(b)-offset {
			continue
		}
		entries = append(entries, icoEntry{size: size, bpp: int(binary.LittleEndian.Uint16(e[6:8])), data: b[offset : offset+length]})
	}
	slices.SortStableFunc(entries, func(a, c icoEntry) int {
		if a.size != c.size {
			return c.size - a.size
		}
		return c.bpp - a.bpp
	})
	for _, e := range entries {
		if bytes.HasPrefix(e.data, pngSignature) {
			if _, err := png.DecodeConfig(bytes.NewReader(e.data)); err == nil {
				return bytes.Clone(e.data), nil
			}
			continue
		}
		if img, err := decodeICOBitmap(e.data); err == nil {
			return encodePNG(img)
		}
	}
	return nil, errBadIcon
}

// decodeICOBitmap decodes the headerless BMP of an .ico entry: a
// BITMAPINFOHEADER, an optional palette, bottom-up pixel rows and a 1-bit
// AND mask, with the height counting both.
func decodeICOBitmap(d []byte) (image.Image, error) {
	if len(d) < 40 {
		return nil, errBadIcon
	}
	headerSize := int(binary.LittleEndian.Uint32(d[0:4]))
	w := int(int32(binary.LittleEndian.Uint32(d[4:8])))
	h := int(int32(binary.LittleEndian.Uint32(d[8:12]))) / 2
	bpp := int(binary.LittleEndian.Uint16(d[14:16]))
	compression := binary.LittleEndian.Uint32(d[16:20])
	colors := int(binary.LittleEndian.Uint32(d[32:36]))
	if headerSize < 40 || headerSize > len(d) || w <= 0 || h <= 0 || w > 256 || h > 256 || compression != 0 {
		return nil, errBadIcon
	}
	var palette []color.NRGBA
	if bpp <= 8 {
		switch bpp {
		case 1, 4, 8:
		default:
			return nil, errBadIcon
		}
		if colors == 0 {
			colors = 1 << bpp
		}
		end := headerSize + 4*colors
		if end > len(d) {
			return nil, errBadIcon
		}
		for i := range colors {
			p := d[headerSize+4*i:]
			palette = append(palette, color.NRGBA{R: p[2], G: p[1], B: p[0], A: 255})
		}
		headerSize = end
	} else if bpp != 24 && bpp != 32 {
		return nil, errBadIcon
	}

	stride := (w*bpp + 31) / 32 * 4
	maskStride := (w + 31) / 32 * 4
	pixels := d[headerSize:]
	if len(pixels) < stride*h {
		return nil, errBadIcon
	}
	var mask []byte
	if rest := pixels[stride*h:]; len(rest) >= maskStride*h {
		mask = rest
	}

	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	anyAlpha := false
	for y := range h {
		row := pixels[(h-1-y)*stride:]
		for x := range w {
			var c color.NRGBA
			switch bpp {
			case 32:
				c = color.NRGBA{R: row[4*x+2], G: row[4*x+1], B: row[4*x], A: row[4*x+3]}
				anyAlpha = anyAlpha || c.A != 0
			case 24:
				c = color.NRGBA{R: row[3*x+2], G: row[3*x+1], B: row[3*x], A: 255}
			default:
				idx := int(row[x*bpp/8]>>(8-bpp-(x*bpp)%8)) & (1<<bpp - 1)
				if idx < len(palette) {
					c = palette[idx]
				}
			}
			img.SetNRGBA(x, y, c)
		}
	}
	if mask != nil && (bpp != 32 || !anyAlpha) {
		for y := range h {
			row := mask[(h-1-y)*maskStride:]
			for x := range w {
				if row[x/8]&(0x80>>(x%8)) != 0 {
					img.Pix[img.PixOffset(x, y)+3] = 0
				} else if bpp == 32 {
					img.Pix[img.PixOffset(x, y)+3] = 255
				}
			}
		}
	}
	return img, nil
}
