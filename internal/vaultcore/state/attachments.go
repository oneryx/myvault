package state

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/oneryx/myvault/internal/vaultcore/api"
	"github.com/oneryx/myvault/internal/vaultcore/crypto"
	"github.com/oneryx/myvault/internal/vaultcore/store"
)

func (s *Service) DownloadAttachment(ctx context.Context, cipherID, attachmentID string) ([]byte, string, error) {
	o, err := s.beginOp(ctx)
	if err != nil {
		return nil, "", err
	}
	defer o.end()

	c, att, err := o.lookupAttachment(cipherID, attachmentID, false)
	if err != nil {
		return nil, "", err
	}
	cipherKey, err := o.cipherKey(c)
	if err != nil {
		return nil, "", err
	}
	defer cipherKey.Zero()

	meta, err := withAuth(o, func(ctx context.Context, tok string) (*api.EncryptedAttachment, error) {
		return o.client.GetAttachment(ctx, tok, cipherID, attachmentID)
	})
	if err != nil {
		return nil, "", err
	}
	if meta.Key != nil && *meta.Key != "" {
		att.Key = meta.Key
	}
	encData, err := withAuth(o, func(ctx context.Context, tok string) ([]byte, error) {
		return o.client.DownloadAttachmentBytes(ctx, tok, meta.URL)
	})
	if err != nil {
		return nil, "", err
	}

	attKey, err := attachmentKey(att.Key, cipherKey)
	if err != nil {
		return nil, "", err
	}
	defer attKey.Zero()
	plain, err := crypto.DecryptBuffer(encData, attKey)
	if err != nil {
		return nil, "", err
	}
	if !o.current() {
		crypto.ZeroBytes(plain)
		return nil, "", ErrLocked
	}
	return plain, att.FileName, nil
}

func (s *Service) UploadAttachment(ctx context.Context, cipherID, fileName string, plain []byte) (*Cipher, error) {
	if len(plain) > api.MaxAttachmentSize {
		return nil, api.ErrAttachmentTooLarge
	}
	o, err := s.beginOp(ctx)
	if err != nil {
		return nil, err
	}
	defer o.end()

	c, err := o.editableCipher(cipherID)
	if err != nil {
		return nil, err
	}
	cipherKey, err := o.cipherKey(c)
	if err != nil {
		return nil, err
	}
	defer cipherKey.Zero()

	attKey, err := crypto.GenerateSymmetricKey()
	if err != nil {
		return nil, err
	}
	defer attKey.Zero()
	rawAttKey := attKey.Bytes()
	encAttKey, err := crypto.EncryptBytes(rawAttKey[:], cipherKey)
	crypto.ZeroBytes(rawAttKey[:])
	if err != nil {
		return nil, err
	}
	encName, err := crypto.EncryptString(fileName, cipherKey)
	if err != nil {
		return nil, err
	}
	data, err := crypto.EncryptBuffer(plain, attKey)
	if err != nil {
		return nil, err
	}

	created, err := withAuth(o, func(ctx context.Context, tok string) (*api.AttachmentUploadResponse, error) {
		return o.client.CreateAttachmentV2(ctx, tok, cipherID, api.AttachmentUploadRequest{
			Key: encAttKey.String(), FileName: encName, FileSize: int64(len(data)),
		})
	})
	if err != nil {
		return nil, err
	}
	if created.FileUploadType != api.FileUploadTypeDirect {
		o.discardAttachment(cipherID, created.AttachmentID)
		return nil, ErrUnsupportedUpload
	}
	_, err = withAuth(o, func(ctx context.Context, tok string) (struct{}, error) {
		return struct{}{}, o.client.UploadAttachmentData(ctx, tok, cipherID, created.AttachmentID, encName, data)
	})
	if err != nil {
		o.discardAttachment(cipherID, created.AttachmentID)
		return nil, err
	}
	return o.refreshCipher(c, created.CipherResponse)
}

func (s *Service) DeleteAttachment(ctx context.Context, cipherID, attachmentID string) (*Cipher, error) {
	o, err := s.beginOp(ctx)
	if err != nil {
		return nil, err
	}
	defer o.end()

	c, _, err := o.lookupAttachment(cipherID, attachmentID, true)
	if err != nil {
		return nil, err
	}
	_, err = withAuth(o, func(ctx context.Context, tok string) (struct{}, error) {
		return struct{}{}, o.client.DeleteAttachment(ctx, tok, cipherID, attachmentID)
	})
	if err != nil {
		return nil, err
	}
	return o.refreshCipher(c, nil)
}

func (o *op) discardAttachment(cipherID, attachmentID string) {
	if attachmentID == "" {
		return
	}
	_, _ = withAuth(o, func(ctx context.Context, tok string) (struct{}, error) {
		return struct{}{}, o.client.DeleteAttachment(ctx, tok, cipherID, attachmentID)
	})
}

// lookupAttachment finds the attachment after checking the organization
// permissions: hidden passwords forbid downloads, read-only forbids changes.
func (o *op) lookupAttachment(cipherID, attachmentID string, modify bool) (*Cipher, Attachment, error) {
	o.s.mu.RLock()
	defer o.s.mu.RUnlock()
	if !o.currentLocked() {
		return nil, Attachment{}, ErrLocked
	}
	c, ok := o.s.ciphers[cipherID]
	if !ok {
		return nil, Attachment{}, ErrCipherNotFound
	}
	if modify && o.s.effectiveReadOnlyLocked(c) {
		return nil, Attachment{}, ErrReadOnlyCipher
	}
	if !modify && o.s.effectiveHidePasswordLocked(c) {
		return nil, Attachment{}, ErrHiddenByOrganization
	}
	for _, a := range c.Attachments {
		if a.ID == attachmentID {
			cp := cloneCipher(c)
			return cp, a, nil
		}
	}
	return nil, Attachment{}, ErrAttachmentNotFound
}

// cipherKey returns a copy of the key that encrypts the fields of c.
func (o *op) cipherKey(c *Cipher) (*crypto.SymmetricKey, error) {
	key, err := o.itemKey(c.OrganizationID)
	if err != nil {
		return nil, err
	}
	if c.Key == nil || *c.Key == "" {
		return key, nil
	}
	defer key.Zero()
	raw, err := decryptBytesFromString(*c.Key, key)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(raw)
	return crypto.SymmetricKeyFromBytes(raw)
}

func attachmentKey(encKey *string, cipherKey *crypto.SymmetricKey) (*crypto.SymmetricKey, error) {
	if encKey == nil || *encKey == "" {
		raw := cipherKey.Bytes()
		defer crypto.ZeroBytes(raw[:])
		return crypto.SymmetricKeyFromBytes(raw[:])
	}
	raw, err := decryptBytesFromString(*encKey, cipherKey)
	if err != nil {
		return nil, err
	}
	defer crypto.ZeroBytes(raw)
	return crypto.SymmetricKeyFromBytes(raw)
}

// refreshCipher reloads the cipher from the server, falling back to fallback,
// and stores it in memory and in the encrypted snapshot.
func (o *op) refreshCipher(prev *Cipher, fallback *api.EncryptedCipher) (*Cipher, error) {
	enc, err := withAuth(o, func(ctx context.Context, tok string) (*api.EncryptedCipher, error) {
		return o.client.GetCipher(ctx, tok, prev.ID)
	})
	if err != nil {
		if fallback == nil {
			return nil, err
		}
		enc = fallback
	}
	key, err := o.itemKey(enc.OrganizationID)
	if err != nil {
		return nil, err
	}
	defer key.Zero()
	decrypted, err := decryptCipher(enc, key)
	if err != nil {
		return nil, err
	}
	if len(decrypted.CollectionIDs) == 0 {
		decrypted.CollectionIDs = append([]string(nil), prev.CollectionIDs...)
	}

	return o.commitCipher(decrypted, enc)
}

// replaceSnapshotCipher returns a snapshot edit that replaces or adds enc.
func replaceSnapshotCipher(enc *api.EncryptedCipher) func(resp *api.SyncResponse) {
	return func(resp *api.SyncResponse) {
		for i := range resp.Ciphers {
			if resp.Ciphers[i].ID == enc.ID {
				if len(enc.CollectionIDs) == 0 {
					enc.CollectionIDs = resp.Ciphers[i].CollectionIDs
				}
				resp.Ciphers[i] = *enc
				return
			}
		}
		resp.Ciphers = append(resp.Ciphers, *enc)
	}
}

// updateSnapshot commits a change the server accepted: edit rewrites the
// encrypted snapshot on disk, then apply (run under s.mu) updates memory.
// Both happen under persistMu, so no sync or other change interleaves, and
// the publication marks syncs fetched earlier as stale.
//
// Memory is updated even when the disk write fails, since the server has
// the change; that failure is returned as a *LocalCopyError.
func (o *op) updateSnapshot(edit func(resp *api.SyncResponse), apply func()) error {
	return o.updateSnapshotFrom(false, edit, apply)
}

// errSnapshotMoved means the vault changed since the operation began, so
// its result was not committed.
var errSnapshotMoved = errors.New("state: the vault changed during the request")

// updateSnapshotFrom is updateSnapshot; with ifUnchanged it commits only if
// no other change was published since o began, and else returns
// errSnapshotMoved and changes nothing.
func (o *op) updateSnapshotFrom(ifUnchanged bool, edit func(resp *api.SyncResponse), apply func()) error {
	s := o.s
	s.persistMu.Lock()
	defer s.persistMu.Unlock()
	s.mu.RLock()
	snap, ok, seq := s.snapshot, o.currentLocked(), s.snapSeq
	s.mu.RUnlock()
	if !ok {
		return ErrLocked
	}
	if ifUnchanged && seq != o.seq {
		return errSnapshotMoved
	}
	updated, diskErr := o.writeSnapshot(snap, edit)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !o.currentLocked() {
		return ErrLocked
	}
	if updated != nil {
		s.snapshot = updated
	}
	s.snapSeq++
	if apply != nil {
		apply()
	}
	if diskErr != nil {
		return &LocalCopyError{Err: diskErr}
	}
	return nil
}

func (o *op) writeSnapshot(snap *store.Snapshot, edit func(resp *api.SyncResponse)) (*store.Snapshot, error) {
	if snap == nil {
		return nil, ErrLoggedOut
	}
	var resp api.SyncResponse
	if err := json.Unmarshal(snap.RawSyncJSON, &resp); err != nil {
		return nil, err
	}
	edit(&resp)
	raw, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	updated := *snap
	updated.RawSyncJSON = raw
	if err := o.s.cfg.Store.SaveSnapshot(&updated); err != nil {
		return nil, err
	}
	return &updated, nil
}
