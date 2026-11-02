package config

import (
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte(goalExample))
	f.Add(Example)
	f.Add([]byte("version: 1\n"))
	f.Add([]byte("{"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Parse(data)
		if err != nil {
			if strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("an error echoed a secret: %v", err)
			}
			return
		}
		if c.Fingerprint != nil && c.Fingerprint.DSN.IsZero() {
			t.Fatal("accepted a fingerprint with no DSN reference")
		}
	})
}
