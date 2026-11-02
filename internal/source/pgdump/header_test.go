package pgdump

import (
	"bytes"
	"errors"
	"testing"
)

func writeInt(b *bytes.Buffer, v int) {
	b.WriteByte(0)
	for i := range 4 {
		b.WriteByte(byte(v >> (8 * i)))
	}
}

func writeStr(b *bytes.Buffer, s string) {
	writeInt(b, len(s))
	b.WriteString(s)
}

func fixture(format byte, minor byte, server, tool string) []byte {
	var b bytes.Buffer
	b.WriteString("PGDMP")
	b.Write([]byte{1, minor, 0, 4, 8, format})
	if minor >= 15 {
		b.WriteByte(1)
	} else {
		writeInt(&b, -1)
	}
	for _, v := range []int{7, 30, 2, 1, 10, 126, 0} {
		writeInt(&b, v)
	}
	writeStr(&b, "billing")
	writeStr(&b, server)
	writeStr(&b, tool)
	return b.Bytes()
}

func TestReadHeader(t *testing.T) {
	h, err := ReadHeader(bytes.NewReader(fixture(formatCustom, 15, "17.2", "17.2 (Debian 17.2-1)")))
	if err != nil {
		t.Fatal(err)
	}
	if h.Format != "custom" || h.Database != "billing" || h.ServerMajor != 17 || h.ToolMajor != 17 {
		t.Fatalf("%+v", h)
	}
	if got := h.Created.Format("2006-01-02 15:04:05"); got != "2026-11-01 02:30:07" {
		t.Fatalf("created = %s", got)
	}
}

func TestReadHeaderOlderFormat(t *testing.T) {
	h, err := ReadHeader(bytes.NewReader(fixture(formatDirectory, 14, "14.9", "14.9")))
	if err != nil {
		t.Fatal(err)
	}
	if h.Format != "directory" || h.ServerMajor != 14 {
		t.Fatalf("%+v", h)
	}
}

func TestReadHeaderRejectsBadInput(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":     {},
		"garbage":   []byte("this is not an archive at all, not even close"),
		"plain sql": []byte("--\n-- PostgreSQL database dump\n--\n"),
		"truncated": fixture(formatCustom, 15, "17.2", "17.2")[:12],
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReadHeader(bytes.NewReader(in)); !errors.Is(err, ErrNotArchive) {
				t.Fatalf("got %v", err)
			}
		})
	}

	tarFile := append([]byte("toc.dat\x00\x00\x00"), make([]byte, 500)...)
	if _, err := ReadHeader(bytes.NewReader(tarFile)); !errors.Is(err, ErrNotArchive) {
		t.Fatalf("got %v", err)
	}
}

func TestDirectoryArchiveTOCCarriesTheTarCode(t *testing.T) {
	h, err := ReadHeader(bytes.NewReader(fixture(formatTar, 15, "17.2", "17.2")))
	if err != nil {
		t.Fatal(err)
	}
	if h.Format != "directory" {
		t.Fatalf("%+v", h)
	}
}

func TestSafeName(t *testing.T) {
	for _, ok := range []string{"billing-1.dump", "billing-1.dir/toc.dat", "a/b/c.dat"} {
		if !safeName(ok) {
			t.Errorf("%q should be accepted", ok)
		}
	}
	for _, bad := range []string{"", "../etc/passwd", "a/../../b", "/abs", "a//b", "a/./b", `a\b`, ".."} {
		if safeName(bad) {
			t.Errorf("%q must be refused", bad)
		}
	}
}
