package pgbackrest

import "testing"

func FuzzParseListing(f *testing.F) {
	f.Add([]byte(`{"17-1/0000000100000000/000000010000000000000003-be02dd46e3ca8955c8360d736aba238946997a91.gz":{"type":"file"},"17-1/00000002.history":{"type":"file"}}`), int64(wal16MB))
	f.Add([]byte(`{}`), int64(1<<20))
	f.Fuzz(func(t *testing.T, data []byte, walSize int64) {
		if walSize < 1<<20 || walSize > 1<<30 || walSize&(walSize-1) != 0 {
			return
		}
		l, err := parseListing(data, walSize)
		if err != nil {
			return
		}
		_, _ = buildPlan(l, "000000010000000000000003", "000000010000000000000004", nil, walSize)
	})
}

func FuzzParseHistory(f *testing.F) {
	f.Add("1\t0/5000100\tno recovery target specified\n")
	f.Add("garbage")
	f.Fuzz(func(t *testing.T, text string) {
		points, err := parseHistory(text)
		if err != nil {
			return
		}
		histories := map[uint32][]switchPoint{2: points}
		l := listing{segments: map[uint32]map[uint64]bool{1: {3: true}, 2: {5: true}}}
		_, _ = buildPlan(l, "000000010000000000000003", "000000010000000000000003", histories, wal16MB)
	})
}

func FuzzParseVerify(f *testing.F) {
	f.Add("stanza: demo\nstatus: ok\n  backup: x, status: valid, total files checked: 9, total valid files: 9\n")
	f.Add("stanza: demo\nstatus: error\n    missing: 0, checksum invalid: 1, size invalid: 0, other: 0\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, text string) {
		ok, _ := parseVerify(text)
		if ok && !verifyStatus.MatchString(text) {
			t.Fatalf("passed output with no status line: %q", text)
		}
	})
}
