package pgdump

import (
	"bytes"
	"testing"
)

func FuzzReadHeader(f *testing.F) {
	f.Add(fixture(formatCustom, 15, "17.2", "17.2"))
	f.Add(fixture(formatDirectory, 14, "14.9", "14.9"))
	f.Add([]byte("PGDMP"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := ReadHeader(bytes.NewReader(data))
		if err == nil && (h.ServerMajor <= 0 || h.ToolMajor <= 0 || h.Format == "") {
			t.Fatalf("accepted a header without versions: %+v", h)
		}
	})
}

func FuzzSafeName(f *testing.F) {
	for _, s := range []string{"a", "a/b", "../x", "a/../b", "/x", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if !safeName(name) {
			return
		}
		depth := 0
		for _, part := range bytes.Split([]byte(name), []byte("/")) {
			if string(part) == ".." {
				depth--
			} else {
				depth++
			}
			if depth < 0 {
				t.Fatalf("%q escapes", name)
			}
		}
	})
}
