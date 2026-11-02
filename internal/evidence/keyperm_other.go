//go:build !windows

package evidence

import (
	"fmt"
	"os"
)

func restrictKey(string) error { return nil }

func checkKeyAccess(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("read signing key: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s can be read by other users (mode %04o); restrict it with chmod 600", path, st.Mode().Perm())
	}
	return nil
}
