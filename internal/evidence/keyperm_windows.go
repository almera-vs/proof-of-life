//go:build windows

package evidence

import (
	"fmt"

	"golang.org/x/sys/windows"
)

const ownerOnly = "D:P(A;;FA;;;OW)(A;;FA;;;SY)"

func restrictKey(path string) error {
	sd, err := windows.SecurityDescriptorFromString(ownerOnly)
	if err != nil {
		return fmt.Errorf("build key permissions: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("build key permissions: %w", err)
	}
	err = windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
	if err != nil {
		return fmt.Errorf("restrict key permissions: %w", err)
	}
	return nil
}

func checkKeyAccess(string) error { return nil }
