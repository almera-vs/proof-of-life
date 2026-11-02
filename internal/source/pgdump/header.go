package pgdump

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"
)

const (
	formatCustom    = 1
	formatTar       = 3
	formatDirectory = 5
)

type Header struct {
	Format      string
	Created     time.Time
	Database    string
	ServerVer   string
	ToolVer     string
	ServerMajor int
	ToolMajor   int
}

var ErrNotArchive = errors.New("the file has no pg_dump archive header")

var majorPattern = regexp.MustCompile(`^(\d+)`)

func ReadHeader(r io.Reader) (Header, error) {
	br := bufio.NewReader(r)
	p := headerReader{r: br}
	magic := p.bytes(5)
	if p.err != nil || string(magic) != "PGDMP" {
		return Header{}, ErrNotArchive
	}
	vmaj, vmin, vrev := p.byte(), p.byte(), p.byte()
	version := int(vmaj)*10000 + int(vmin)*100 + int(vrev)
	p.intSize = int(p.byte())
	p.byte()
	code := p.byte()
	if p.err != nil {
		return Header{}, fmt.Errorf("%w: truncated", ErrNotArchive)
	}
	if p.intSize < 1 || p.intSize > 8 {
		return Header{}, fmt.Errorf("%w: implausible integer size %d", ErrNotArchive, p.intSize)
	}
	if version < 11000 {
		return Header{}, fmt.Errorf("archive format %d.%d is older than any supported pg_dump", vmaj, vmin)
	}
	h := Header{}
	switch code {
	case formatCustom:
		h.Format = "custom"
	case formatDirectory, formatTar:

		h.Format = "directory"
	default:
		return h, fmt.Errorf("%w: unknown format code %d", ErrNotArchive, code)
	}
	if version >= 11500 {
		p.byte()
	} else {
		p.int()
	}
	sec, minute, hour, day, month, year := p.int(), p.int(), p.int(), p.int(), p.int(), p.int()
	p.int()
	h.Created = time.Date(year+1900, time.Month(month+1), day, hour, minute, sec, 0, time.UTC)
	h.Database = p.str()
	h.ServerVer = p.str()
	h.ToolVer = p.str()
	if p.err != nil {
		return h, fmt.Errorf("%w: truncated", ErrNotArchive)
	}
	var err error
	if h.ServerMajor, err = major(h.ServerVer); err != nil {
		return h, fmt.Errorf("read server version from archive: %w", err)
	}
	if h.ToolMajor, err = major(h.ToolVer); err != nil {
		return h, fmt.Errorf("read pg_dump version from archive: %w", err)
	}

	for _, v := range []int{h.ServerMajor, h.ToolMajor} {
		if v < minMajor || v > maxMajor {
			return h, fmt.Errorf("%w: implausible PostgreSQL version %d", ErrNotArchive, v)
		}
	}
	if y := h.Created.Year(); y < 1996 || y > 9999 {
		return h, fmt.Errorf("%w: implausible creation year %d", ErrNotArchive, y)
	}
	return h, nil
}

const (
	minMajor = 8
	maxMajor = 99
)

func major(version string) (int, error) {
	m := majorPattern.FindStringSubmatch(version)
	if m == nil {
		return 0, fmt.Errorf("unrecognised version %q", version)
	}
	return strconv.Atoi(m[1])
}

type headerReader struct {
	r       *bufio.Reader
	intSize int
	err     error
}

func (p *headerReader) bytes(n int) []byte {
	if p.err != nil {
		return nil
	}
	b := make([]byte, n)
	_, p.err = io.ReadFull(p.r, b)
	return b
}

func (p *headerReader) byte() byte {
	b := p.bytes(1)
	if p.err != nil {
		return 0
	}
	return b[0]
}

func (p *headerReader) int() int {
	sign := p.byte()
	b := p.bytes(p.intSize)
	if p.err != nil {
		return 0
	}
	v := 0
	for i, c := range b {
		v |= int(c) << (8 * i)
	}
	if sign != 0 {
		return -v
	}
	return v
}

func (p *headerReader) str() string {
	n := p.int()
	if p.err != nil || n <= 0 {
		return ""
	}
	if n > 4096 {
		p.err = errors.New("implausible string length")
		return ""
	}
	return string(p.bytes(n))
}
