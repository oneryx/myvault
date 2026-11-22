package totp

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestVector9_RFC6238SHA1(t *testing.T) {
	cfg, err := ParseTOTP("otpauth://totp/RFC6238?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA1&digits=8&period=30")
	if err != nil {
		t.Fatalf("ParseTOTP failed: %v", err)
	}

	cases := []struct {
		unix          int64
		wantCode      string
		wantRemaining int
	}{
		{59, "94287082", 1},
		{1111111109, "07081804", 1},
		{1234567890, "89005924", 30},
		{2000000000, "69279037", 10},
	}

	for _, tc := range cases {
		code, remaining, period, err := Generate(cfg, time.Unix(tc.unix, 0).UTC())
		if err != nil {
			t.Fatalf("Generate(t=%d) failed: %v", tc.unix, err)
		}
		if code != tc.wantCode {
			t.Errorf("t=%d: code = %q, want %q", tc.unix, code, tc.wantCode)
		}
		if remaining != tc.wantRemaining || period != 30 {
			t.Errorf("t=%d: remaining=%d period=%d, want %d/30", tc.unix, remaining, period, tc.wantRemaining)
		}
	}
}

func TestVector9_BitwardenFormats(t *testing.T) {
	t.Run("bare base32 with spaces and lowercase", func(t *testing.T) {
		cfg, err := ParseTOTP("jbsw y3dp ehpk 3pxp")
		if err != nil {
			t.Fatalf("ParseTOTP failed: %v", err)
		}
		if cfg.Algorithm != "SHA1" || cfg.Digits != 6 || cfg.Period != 30 || cfg.Steam {
			t.Fatalf("unexpected defaults: %+v", cfg)
		}
		code, _, _, err := Generate(cfg, time.Unix(1234567890, 0).UTC())
		if err != nil || len(code) != 6 {
			t.Fatalf("Generate = (%q, %v), want 6-digit code", code, err)
		}
	})

	t.Run("standard otpauth URI with SHA256", func(t *testing.T) {
		uri := "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=6&period=30"
		cfg, err := ParseTOTP(uri)
		if err != nil {
			t.Fatalf("ParseTOTP failed: %v", err)
		}
		if cfg.Algorithm != "SHA256" || cfg.Digits != 6 || cfg.Period != 30 {
			t.Fatalf("unexpected config: %+v", cfg)
		}
		code, _, _, err := Generate(cfg, time.Unix(1234567890, 0).UTC())
		if err != nil || len(code) != 6 {
			t.Fatalf("Generate = (%q, %v), want 6-digit code", code, err)
		}
	})

	t.Run("unpadded base32 secret", func(t *testing.T) {
		cfg, err := ParseTOTP("JBSWY3DPEHPK3PX")
		if err != nil {
			t.Fatalf("ParseTOTP unpadded failed: %v", err)
		}
		if len(cfg.Secret) == 0 {
			t.Fatalf("expected non-empty decoded secret")
		}
	})

	t.Run("steam prefix", func(t *testing.T) {
		cfg, err := ParseTOTP("steam://JBSWY3DPEHPK3PXP")
		if err != nil {
			t.Fatalf("ParseTOTP steam failed: %v", err)
		}
		if !cfg.Steam || cfg.Digits != 5 {
			t.Fatalf("unexpected steam config: %+v", cfg)
		}
		code, _, _, err := Generate(cfg, time.Unix(1234567890, 0).UTC())
		if err != nil || len(code) != 5 {
			t.Fatalf("Generate steam = (%q, %v), want 5-char code", code, err)
		}
		for _, r := range code {
			if !strings.ContainsRune(steamAlphabet, r) {
				t.Errorf("steam code %q contains invalid char %q", code, r)
			}
		}
	})
}

func TestParseTOTP_RejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr error
	}{
		{"empty", "   ", ErrInvalidTOTP},
		{"bad base32", "!!!not-base32!!!", ErrInvalidSecret},
		{"hotp rejected", "otpauth://hotp/Test?secret=JBSWY3DPEHPK3PXP", ErrUnsupportedParam},
		{"missing secret", "otpauth://totp/Test?issuer=Example", ErrInvalidSecret},
		{"unsupported algorithm", "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&algorithm=MD5", ErrUnsupportedParam},
		{"unsupported digits", "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=7", ErrUnsupportedParam},
		{"invalid period", "otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&period=0", ErrInvalidTOTP},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseTOTP(tc.input); !errors.Is(err, tc.wantErr) {
				t.Fatalf("ParseTOTP(%q) = %v, want %v", tc.input, err, tc.wantErr)
			}
		})
	}
}
