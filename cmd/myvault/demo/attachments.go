package demo

import (
	"bytes"
	"context"
	"fmt"
	"slices"

	"github.com/oneryx/myvault/internal/vaultcore/state"
)

func (s *Service) DownloadAttachment(_ context.Context, cipherID, attachmentID string) ([]byte, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.ciphers[cipherID]
	if !ok || s.status != state.StatusUnlocked {
		return nil, "", state.ErrCipherNotFound
	}
	for _, a := range c.Attachments {
		if a.ID == attachmentID {
			return bytes.Clone(s.blobs[a.ID]), a.FileName, nil
		}
	}
	return nil, "", state.ErrAttachmentNotFound
}

func (s *Service) UploadAttachment(_ context.Context, cipherID, fileName string, plain []byte) (*state.Cipher, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.ciphers[cipherID]
	if !ok {
		return nil, state.ErrCipherNotFound
	}
	s.nextID++
	id := fmt.Sprintf("a-new-%d", s.nextID)
	s.blobs[id] = bytes.Clone(plain)
	c.Attachments = append(slices.Clone(c.Attachments), state.Attachment{ID: id, FileName: fileName, Size: int64(len(plain))})
	cp := *c
	return &cp, nil
}

func (s *Service) DeleteAttachment(_ context.Context, cipherID, attachmentID string) (*state.Cipher, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.ciphers[cipherID]
	if !ok {
		return nil, state.ErrCipherNotFound
	}
	c.Attachments = slices.DeleteFunc(slices.Clone(c.Attachments), func(a state.Attachment) bool { return a.ID == attachmentID })
	delete(s.blobs, attachmentID)
	cp := *c
	return &cp, nil
}
