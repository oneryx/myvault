package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/oneryx/myvault/internal/vaultcore/api"
)

func (env *vaultTestEnv) handleAttachments(w http.ResponseWriter, r *http.Request) bool {
	env.mu.Lock()
	defer env.mu.Unlock()
	const prefix = "/api/ciphers/c-1"
	c, exists := env.ciphers["c-1"]
	if id, ok := strings.CutPrefix(r.URL.Path, "/api/ciphers/"); ok && r.Method == http.MethodDelete && !strings.Contains(id, "/") {
		if _, exists := env.ciphers[id]; !exists {
			w.WriteHeader(http.StatusNotFound)
			return true
		}
		delete(env.ciphers, id)
		return true
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == prefix && exists:
		_ = json.NewEncoder(w).Encode(c)
	case r.Method == http.MethodPost && r.URL.Path == prefix+"/attachment/v2":
		var req api.AttachmentUploadRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		key := req.Key
		c.Attachments = append(c.Attachments, api.EncryptedAttachment{ID: "att-1", FileName: req.FileName, Key: &key, Size: api.FlexInt(req.FileSize), SizeName: "1 KB"})
		env.ciphers["c-1"] = c
		_ = json.NewEncoder(w).Encode(api.AttachmentUploadResponse{AttachmentID: "att-1", FileUploadType: api.FileUploadTypeDirect, CipherResponse: &c})
	case r.Method == http.MethodPost && r.URL.Path == prefix+"/attachment/att-1":
		f, _, err := r.FormFile("data")
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}
		data, _ := io.ReadAll(f)
		if len(c.Attachments) == 0 || int64(c.Attachments[0].Size) != int64(len(data)) {
			w.WriteHeader(http.StatusBadRequest)
			return true
		}
		if env.blobs == nil {
			env.blobs = map[string][]byte{}
		}
		env.blobs["att-1"] = data
	case r.Method == http.MethodGet && r.URL.Path == prefix+"/attachment/att-1":
		if len(c.Attachments) == 0 {
			w.WriteHeader(http.StatusNotFound)
			return true
		}
		a := c.Attachments[0]
		a.URL = env.server.URL + "/attachments/c-1/att-1?token=t"
		_ = json.NewEncoder(w).Encode(a)
	case r.Method == http.MethodGet && r.URL.Path == "/attachments/c-1/att-1":
		env.blobAuth = append(env.blobAuth, r.Header.Get("Authorization"))
		_, _ = w.Write(env.blobs["att-1"])
	case r.Method == http.MethodDelete && r.URL.Path == prefix+"/attachment/att-1":
		c.Attachments = nil
		env.ciphers["c-1"] = c
		delete(env.blobs, "att-1")
	default:
		return false
	}
	return true
}

func TestService_AttachmentUploadDownloadDelete(t *testing.T) {
	env := newVaultTestEnv(t)
	svc := loggedInTestService(t, env)
	ctx := context.Background()
	plain := bytes.Repeat([]byte("secret report \x00\x01"), 64)

	updated, err := svc.UploadAttachment(ctx, "c-1", "report.pdf", plain)
	if err != nil {
		t.Fatalf("UploadAttachment: %v", err)
	}
	if len(updated.Attachments) != 1 || updated.Attachments[0].FileName != "report.pdf" || updated.Attachments[0].ID != "att-1" {
		t.Fatalf("attachments after upload = %+v", updated.Attachments)
	}
	env.mu.Lock()
	blob := env.blobs["att-1"]
	storedName := env.ciphers["c-1"].Attachments[0].FileName
	env.mu.Unlock()
	if bytes.Contains(blob, []byte("secret report")) || blob[0] != 2 || strings.Contains(storedName, "report") {
		t.Fatalf("attachment stored unencrypted")
	}

	svc.Lock()
	if err := svc.UnlockWithPassword(ctx, env.password); err != nil {
		t.Fatalf("UnlockWithPassword: %v", err)
	}
	if c, _ := svc.GetCipher("c-1"); c == nil || len(c.Attachments) != 1 {
		t.Fatalf("snapshot lost the attachment: %+v", c)
	}

	data, name, err := svc.DownloadAttachment(ctx, "c-1", "att-1")
	if err != nil || name != "report.pdf" || !bytes.Equal(data, plain) {
		t.Fatalf("DownloadAttachment = (%d bytes, %q, %v)", len(data), name, err)
	}
	env.mu.Lock()
	auth := env.blobAuth
	env.mu.Unlock()
	if len(auth) != 1 || !strings.HasPrefix(auth[0], "Bearer ") {
		t.Fatalf("same-origin download auth = %v", auth)
	}

	after, err := svc.DeleteAttachment(ctx, "c-1", "att-1")
	if err != nil || len(after.Attachments) != 0 {
		t.Fatalf("DeleteAttachment = (%+v, %v)", after, err)
	}
	if _, _, err := svc.DownloadAttachment(ctx, "c-1", "att-1"); !errors.Is(err, ErrAttachmentNotFound) {
		t.Fatalf("download after delete = %v", err)
	}
}
