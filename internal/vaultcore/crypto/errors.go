package crypto

import "errors"

var (
	ErrInvalidKDF         = errors.New("crypto: invalid KDF configuration")
	ErrInvalidKeyLength   = errors.New("crypto: symmetric key must be 64 bytes")
	ErrInvalidEncString   = errors.New("crypto: invalid EncString format")
	ErrUnsupportedEncType = errors.New("crypto: unsupported EncString type")
	ErrInvalidMAC         = errors.New("crypto: MAC verification failed")
	ErrInvalidIV          = errors.New("crypto: IV must be 16 bytes")
	ErrInvalidPadding     = errors.New("crypto: invalid PKCS#7 padding")
)
