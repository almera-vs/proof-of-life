//go:build !unix

package evidence

import (
	"errors"
	"fmt"
	"os"
	"time"
)

func lock(path string) (func(), error) {
	name := path + ".lock"
	deadline := time.Now().Add(30 * time.Second)
	for {
		f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(name) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("lock evidence log: %w", err)
		}
		if st, statErr := os.Stat(name); statErr == nil && time.Since(st.ModTime()) > 5*time.Minute {
			_ = os.Remove(name)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("the evidence log is locked by %s", name)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
