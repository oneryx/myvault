package crypto

type SymmetricKey struct {
	Enc [32]byte
	Mac [32]byte
}

func (k *SymmetricKey) Zero() {
	if k == nil {
		return
	}
	clear(k.Enc[:])
	clear(k.Mac[:])
}

func (k *SymmetricKey) Bytes() [64]byte {
	var out [64]byte
	if k == nil {
		return out
	}
	copy(out[:32], k.Enc[:])
	copy(out[32:], k.Mac[:])
	return out
}

func SymmetricKeyFromBytes(raw []byte) (*SymmetricKey, error) {
	if len(raw) != 64 {
		return nil, ErrInvalidKeyLength
	}
	k := &SymmetricKey{}
	copy(k.Enc[:], raw[:32])
	copy(k.Mac[:], raw[32:])
	return k, nil
}

func ZeroBytes(b []byte) {
	clear(b)
}
