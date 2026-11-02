//go:build unix

package evidence

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

func lock(path string) (func(), error) {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, fmt.Errorf("lock evidence log: %w", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("lock evidence log: %w", err)
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("the evidence log is locked by another drill: %s.lock", path)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
