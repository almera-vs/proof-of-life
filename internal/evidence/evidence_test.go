package evidence

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type fixture struct {
	dir  string
	log  string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newFixture(t *testing.T, records int) fixture {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	pubPath, err := GenerateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := LoadPrivateKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKey(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{dir: dir, log: filepath.Join(dir, "evidence.jsonl"), priv: priv, pub: pub}
	for i := range records {
		f.add(t, fmt.Sprintf("run%d", i))
	}
	return f
}

func (f fixture) add(t *testing.T, run string) Written {
	t.Helper()
	w, err := Append(f.log, f.priv, Record{
		RunID: run, Drill: "billing", Verdict: "pass", Backup: Backup{Label: "b1", PGMajor: 17},
		Checks: []Check{{ID: "restore.completes", Status: "pass", Observed: "1.5s <ok>", Seconds: 1.5}},
		Phases: []Phase{{Name: "restore", Status: "ok", Seconds: 1.234567}},
		Tools:  Tools{Agent: "pol 0.1.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (f fixture) verify(opts VerifyOptions) (VerifyResult, error) {
	return Verify(f.log, HeadPath(f.log), []ed25519.PublicKey{f.pub}, opts)
}

func (f fixture) lines(t *testing.T) [][]byte {
	t.Helper()
	b, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
}

func (f fixture) write(t *testing.T, lines [][]byte) {
	t.Helper()
	if err := os.WriteFile(f.log, append(bytes.Join(lines, []byte("\n")), '\n'), 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestChainVerifies(t *testing.T) {
	f := newFixture(t, 5)
	res, err := f.verify(VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Records != 5 {
		t.Fatalf("records = %d", res.Records)
	}
}

func TestRecordsLinkToPreviousHash(t *testing.T) {
	f := newFixture(t, 0)
	a := f.add(t, "a")
	b := f.add(t, "b")
	if a.PrevHash != Genesis || a.Seq != 1 {
		t.Fatalf("%+v", a)
	}
	if b.PrevHash != a.Hash || b.Seq != 2 {
		t.Fatalf("%+v", b)
	}
}

func TestEveryEditIsDetected(t *testing.T) {
	edits := map[string]func(string) string{
		"verdict":     func(s string) string { return strings.Replace(s, `"verdict":"pass"`, `"verdict":"fail"`, 1) },
		"check":       func(s string) string { return strings.Replace(s, `"status":"pass"`, `"status":"fail"`, 1) },
		"timing":      func(s string) string { return strings.Replace(s, `1.234567`, `0.234567`, 1) },
		"label":       func(s string) string { return strings.Replace(s, `"label":"b1"`, `"label":"b9"`, 1) },
		"whitespace":  func(s string) string { return strings.Replace(s, `{"v":1,`, `{"v":1, `, 1) },
		"extra field": func(s string) string { return strings.Replace(s, `{"v":1,`, `{"v":1,"note":"x",`, 1) },
		"signature":   func(s string) string { return strings.Replace(s, `"signature":"`, `"signature":"AAAA`, 1) },
	}
	for name, edit := range edits {
		for _, target := range []int{0, 2, 4} {
			t.Run(fmt.Sprintf("%s/record%d", name, target), func(t *testing.T) {
				f := newFixture(t, 5)
				lines := f.lines(t)
				changed := edit(string(lines[target]))
				if changed == string(lines[target]) {
					t.Fatal("the edit changed nothing")
				}
				lines[target] = []byte(changed)
				f.write(t, lines)
				if _, err := f.verify(VerifyOptions{}); err == nil {
					t.Fatal("the edit was not detected")
				}
			})
		}
	}
}

func TestEveryByteFlipIsDetected(t *testing.T) {
	f := newFixture(t, 2)
	original, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	for i := range len(original) - 1 {
		if original[i] == '\n' {
			continue
		}
		mutated := bytes.Clone(original)
		mutated[i] ^= 0x01
		if err := os.WriteFile(f.log, mutated, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := f.verify(VerifyOptions{}); err == nil {
			t.Fatalf("flipping byte %d (%q) was not detected", i, original[i])
		}
	}
}

func TestDeletionIsDetected(t *testing.T) {
	cases := map[string]func([][]byte) [][]byte{
		"first":  func(l [][]byte) [][]byte { return l[1:] },
		"middle": func(l [][]byte) [][]byte { return append(l[:2:2], l[3:]...) },
		"last":   func(l [][]byte) [][]byte { return l[:len(l)-1] },
	}
	for name, del := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 5)
			f.write(t, del(f.lines(t)))
			if _, err := f.verify(VerifyOptions{}); err == nil {
				t.Fatal("the deletion was not detected")
			}
		})
	}
}

func TestEmptiedLogIsDetected(t *testing.T) {
	f := newFixture(t, 3)
	if err := os.WriteFile(f.log, nil, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := f.verify(VerifyOptions{}); err == nil {
		t.Fatal("an emptied log was not detected")
	}
}

func TestReorderingIsDetected(t *testing.T) {
	f := newFixture(t, 3)
	l := f.lines(t)
	l[0], l[1] = l[1], l[0]
	f.write(t, l)
	if _, err := f.verify(VerifyOptions{}); err == nil {
		t.Fatal("the reordering was not detected")
	}
}

func TestMissingHeadFailsUnlessOptional(t *testing.T) {
	f := newFixture(t, 2)
	if err := os.Remove(HeadPath(f.log)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.verify(VerifyOptions{}); err == nil {
		t.Fatal("a missing head must fail")
	}
	res, err := f.verify(VerifyOptions{HeadOptional: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) == 0 {
		t.Fatal("skipping the head must be stated")
	}
}

func TestForgedHeadIsDetected(t *testing.T) {
	f := newFixture(t, 3)
	b, err := os.ReadFile(HeadPath(f.log))
	if err != nil {
		t.Fatal(err)
	}
	forged := strings.Replace(string(b), `"seq":3`, `"seq":2`, 1)
	if err := os.WriteFile(HeadPath(f.log), []byte(forged), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := f.verify(VerifyOptions{}); err == nil {
		t.Fatal("a forged head was not detected")
	}
}

func TestMinSeqAnchorsAgainstRollback(t *testing.T) {
	f := newFixture(t, 3)
	if _, err := f.verify(VerifyOptions{MinSeq: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.verify(VerifyOptions{MinSeq: 4}); err == nil {
		t.Fatal("a log shorter than the anchor must fail")
	}
}

func TestWrongKeyFails(t *testing.T) {
	f := newFixture(t, 1)
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(f.log, HeadPath(f.log), []ed25519.PublicKey{other}, VerifyOptions{}); err == nil {
		t.Fatal("verification with another key must fail")
	}
}

func TestSigningWithAStolenChainIsDetected(t *testing.T) {

	f := newFixture(t, 1)
	_, attacker, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.log); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(HeadPath(f.log)); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(f.log, attacker, Record{RunID: "forged", Verdict: "pass"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.verify(VerifyOptions{}); err == nil {
		t.Fatal("a log signed by another key must fail")
	}
}

func TestAppendRefusesToPaperOverDamage(t *testing.T) {
	t.Run("removed last record", func(t *testing.T) {
		f := newFixture(t, 3)
		l := f.lines(t)
		f.write(t, l[:2])
		if _, err := Append(f.log, f.priv, Record{RunID: "x"}); err == nil {
			t.Fatal("append must refuse a log shorter than its head")
		}
	})
	t.Run("deleted log", func(t *testing.T) {
		f := newFixture(t, 2)
		if err := os.Remove(f.log); err != nil {
			t.Fatal(err)
		}
		if _, err := Append(f.log, f.priv, Record{RunID: "x"}); err == nil {
			t.Fatal("append must refuse when only the head remains")
		}
	})
	t.Run("deleted head", func(t *testing.T) {
		f := newFixture(t, 2)
		if err := os.Remove(HeadPath(f.log)); err != nil {
			t.Fatal(err)
		}
		if _, err := Append(f.log, f.priv, Record{RunID: "x"}); err == nil {
			t.Fatal("append must refuse when the head is missing")
		}
	})
}

func TestKeygenRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if _, err := GenerateKey(path); err != nil {
		t.Fatal(err)
	}
	if _, err := GenerateKey(path); err == nil {
		t.Fatal("keygen must not overwrite a key")
	}
}

func TestCrashBeforeHeadUpdateRecovers(t *testing.T) {
	f := newFixture(t, 2)
	head, err := os.ReadFile(HeadPath(f.log))
	if err != nil {
		t.Fatal(err)
	}
	f.add(t, "interrupted")
	if err := os.WriteFile(HeadPath(f.log), head, 0o640); err != nil {
		t.Fatal(err)
	}
	res, err := f.verify(VerifyOptions{})
	if err != nil {
		t.Fatalf("an honest log must verify: %v", err)
	}
	if res.Records != 3 || len(res.Warnings) != 1 {
		t.Fatalf("%+v", res)
	}
	w := f.add(t, "next")
	if w.Seq != 4 {
		t.Fatalf("%+v", w)
	}
	res, err = f.verify(VerifyOptions{})
	if err != nil || len(res.Warnings) != 0 {
		t.Fatalf("the next drill should bring the head up to date: %v %+v", err, res)
	}
}

func TestCrashDuringFirstRecordRecovers(t *testing.T) {
	f := newFixture(t, 1)

	if err := writeHead(f.log, f.priv, 0, Genesis); err != nil {
		t.Fatal(err)
	}
	if _, err := f.verify(VerifyOptions{}); err != nil {
		t.Fatalf("a signed first record ahead of a zero head is honest: %v", err)
	}
	if err := os.Remove(f.log); err != nil {
		t.Fatal(err)
	}
	if w := f.add(t, "again"); w.Seq != 1 {
		t.Fatalf("%+v", w)
	}
}

func TestTornLastLineRecovers(t *testing.T) {
	f := newFixture(t, 2)
	whole, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	torn := append(bytes.Clone(whole), []byte(`{"v":1,"seq":3,"run_id":"half`)...)
	if err := os.WriteFile(f.log, torn, 0o640); err != nil {
		t.Fatal(err)
	}
	res, err := f.verify(VerifyOptions{})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if res.Records != 2 || len(res.Warnings) != 1 {
		t.Fatalf("%+v", res)
	}
	if w := f.add(t, "next"); w.Seq != 3 {
		t.Fatalf("%+v", w)
	}
	res, err = f.verify(VerifyOptions{})
	if err != nil || res.Records != 3 || len(res.Warnings) != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	kept, err := filepath.Glob(f.log + ".torn-*")
	if err != nil || len(kept) != 1 {
		t.Fatalf("the incomplete line should be kept aside: %v %v", kept, err)
	}
}

func TestTruncatingTheLastRecordIsStillDetected(t *testing.T) {
	f := newFixture(t, 3)
	whole, err := os.ReadFile(f.log)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.log, whole[:len(whole)-40], 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := f.verify(VerifyOptions{}); err == nil {
		t.Fatal("a cut-off record with a head naming it must fail")
	}
	if _, err := Append(f.log, f.priv, Record{RunID: "x"}); err == nil {
		t.Fatal("append must refuse")
	}
}

func TestAppendRefusesARecordEditedInPlace(t *testing.T) {
	f := newFixture(t, 3)
	lines := f.lines(t)

	lines[2] = []byte(strings.Replace(string(lines[2]), `"verdict":"pass"`, `"verdict":"fail"`, 1))
	f.write(t, lines)
	if _, err := Append(f.log, f.priv, Record{RunID: "x"}); err == nil {
		t.Fatal("append must check signatures it holds the key for")
	}
}

func TestKeyRotation(t *testing.T) {
	f := newFixture(t, 2)
	newPath := filepath.Join(f.dir, "new")
	newPub, err := GenerateKey(newPath)
	if err != nil {
		t.Fatal(err)
	}
	newPriv, err := LoadPrivateKey(newPath)
	if err != nil {
		t.Fatal(err)
	}
	pub2, err := LoadPublicKey(newPub)
	if err != nil {
		t.Fatal(err)
	}
	w, err := Append(f.log, newPriv, Record{RunID: "rotated"})
	if err != nil {
		t.Fatal(err)
	}
	if w.OtherKeys != 2 {
		t.Fatalf("records under the old key should be counted: %+v", w)
	}
	if _, err := Verify(f.log, HeadPath(f.log), []ed25519.PublicKey{f.pub, pub2}, VerifyOptions{}); err != nil {
		t.Fatalf("both keys: %v", err)
	}
	if _, err := Verify(f.log, HeadPath(f.log), []ed25519.PublicKey{pub2}, VerifyOptions{}); err == nil {
		t.Fatal("old records need the old key")
	}
	if _, err := Verify(f.log, HeadPath(f.log), []ed25519.PublicKey{f.pub}, VerifyOptions{}); err == nil {
		t.Fatal("new records need the new key")
	}
}

func TestConcurrentAppendsStayOrdered(t *testing.T) {
	f := newFixture(t, 0)
	const writers = 16
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := Append(f.log, f.priv, Record{RunID: fmt.Sprintf("r%d", i), Verdict: "pass"})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	res, err := f.verify(VerifyOptions{})
	if err != nil || res.Records != writers {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestKeyReadableByOthersIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows uses an ACL, set when the key is created")
	}
	path := filepath.Join(t.TempDir(), "key")
	if _, err := GenerateKey(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("got %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(path); err != nil {
		t.Fatal(err)
	}
}
