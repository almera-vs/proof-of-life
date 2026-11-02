package evidence

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func FuzzVerify(f *testing.F) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(`{"v":1,"seq":1}` + "\n"))
	f.Add([]byte("\n\n"))
	f.Add([]byte(`{"v":1,"seq":1,"run_id":"x","ts":"t","prev_hash":"` + Genesis + `","drill":"d","verdict":"pass","backup":{},"checks":null,"phases":null,"tools":{"agent":"a"},"key_id":"k","signature":"AAAA"}` + "\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		log := filepath.Join(dir, "e.jsonl")
		if err := os.WriteFile(log, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(log, HeadPath(log), []ed25519.PublicKey{pub}, VerifyOptions{HeadOptional: true}); err == nil {
			t.Fatalf("accepted a log no trusted key signed: %q", data)
		}
	})
}
