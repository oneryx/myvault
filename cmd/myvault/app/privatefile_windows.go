//go:build windows

package app

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// errNoPrivateFiles means the chosen folder cannot keep a file private to
// the user, so nothing is written there.
var errNoPrivateFiles = errors.New("this location cannot keep the file private: its drive has no file permissions (for example FAT32 or exFAT). Choose a folder on an NTFS drive")

// createPrivateTemp creates a new temporary file in dir that only the
// current user can access. Windows ignores Chmod's permission bits, so the
// file is created with a protected DACL granting the user alone full
// access: it inherits nothing from a shared folder. The drive must keep
// that DACL (FAT32 and exFAT have none), and the opened file must carry it,
// before any byte is written; otherwise the file is removed and nothing is
// written. Renaming or hard-linking it keeps that DACL.
func createPrivateTemp(dir, pattern string) (*os.File, error) {
	if err := requirePersistentACLs(dir); err != nil {
		return nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	prefix, suffix, _ := strings.Cut(pattern, "*")
	for range 100 {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return nil, err
		}
		name := filepath.Join(dir, prefix+hex.EncodeToString(b[:])+suffix)
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return nil, err
		}
		h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE|windows.READ_CONTROL, 0, sa,
			windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) {
			continue
		}
		if err != nil {
			return nil, &os.PathError{Op: "create", Path: name, Err: err}
		}
		f := os.NewFile(uintptr(h), name)
		if err := requireUserOnlyDACL(h, user.User.Sid); err != nil {
			_ = f.Close()
			_ = os.Remove(name)
			return nil, err
		}
		return f, nil
	}
	return nil, &os.PathError{Op: "createtemp", Path: filepath.Join(dir, pattern), Err: os.ErrExist}
}

// requirePersistentACLs refuses a folder whose volume does not store file
// permissions.
func requirePersistentACLs(dir string) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	p, err := windows.UTF16PtrFromString(abs)
	if err != nil {
		return err
	}
	root := make([]uint16, windows.MAX_PATH+1)
	if err := windows.GetVolumePathName(p, &root[0], uint32(len(root))); err != nil {
		return err
	}
	var flags uint32
	if err := windows.GetVolumeInformation(&root[0], nil, 0, nil, nil, &flags, nil, 0); err != nil {
		return err
	}
	if flags&windows.FILE_PERSISTENT_ACLS == 0 {
		return errNoPrivateFiles
	}
	return nil
}

// requireUserOnlyDACL checks that the open file has the protected DACL it
// was created with: one entry, full access for the current user.
func requireUserOnlyDACL(h windows.Handle, user *windows.SID) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return checkUserOnlyDACL(sd, user)
}

func checkUserOnlyDACL(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID) error {
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || control&windows.SE_DACL_PROTECTED == 0 || dacl.AceCount != 1 {
		return errNoPrivateFiles
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		return err
	}
	sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !sid.Equals(user) {
		return errNoPrivateFiles
	}
	return nil
}
