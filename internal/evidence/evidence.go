package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/almera-vs/proof-of-life/internal/obs"
)

var Genesis = "sha256:" + strings.Repeat("0", 64)

type Check struct {
	ID       string   `json:"id"`
	Status   string   `json:"status"`
	Severity string   `json:"severity,omitempty"`
	Observed string   `json:"observed,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Controls []string `json:"controls,omitempty"`
	Seconds  float64  `json:"seconds"`
}

type Phase struct {
	Name    string  `json:"name"`
	Status  string  `json:"status"`
	Seconds float64 `json:"seconds"`
}

type Backup struct {
	Label       string `json:"label,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Tool        string `json:"tool,omitempty"`
	ToolVersion string `json:"tool_version,omitempty"`
	PGMajor     int    `json:"pg_major,omitempty"`
	StartLSN    string `json:"start_lsn,omitempty"`
	StopLSN     string `json:"stop_lsn,omitempty"`
	StartTime   string `json:"start_time,omitempty"`
	StopTime    string `json:"stop_time,omitempty"`
	SizeBytes   int64  `json:"size_bytes,omitempty"`
}

type Tools struct {
	Agent  string `json:"agent"`
	Backup string `json:"backup,omitempty"`
	Server string `json:"server,omitempty"`
}

type Record struct {
	Version    int     `json:"v"`
	Seq        uint64  `json:"seq"`
	RunID      string  `json:"run_id"`
	Timestamp  string  `json:"ts"`
	PrevHash   string  `json:"prev_hash"`
	Drill      string  `json:"drill"`
	Verdict    string  `json:"verdict"`
	Backup     Backup  `json:"backup"`
	Checks     []Check `json:"checks"`
	Phases     []Phase `json:"phases"`
	RTOSeconds float64 `json:"rto_seconds,omitempty"`
	Tools      Tools   `json:"tools"`
	KeyID      string  `json:"key_id"`
	Signature  string  `json:"signature,omitempty"`
}

type head struct {
	Seq       uint64 `json:"seq"`
	Hash      string `json:"hash"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

func (h head) signedBytes() []byte {
	return []byte("pol-evidence-head\n" + strconv.FormatUint(h.Seq, 10) + "\n" + h.Hash)
}

func signingBytes(r Record) ([]byte, error) {
	r.Signature = ""
	b, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("encode evidence record: %w", err)
	}
	return b, nil
}

func LineHash(line []byte) string {
	sum := sha256.Sum256(line)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func HeadPath(log string) string { return log + ".head" }

type Written struct {
	Seq      uint64
	Hash     string
	PrevHash string
	KeyID    string

	OtherKeys int
}

func Append(path string, key ed25519.PrivateKey, r Record) (Written, error) {
	unlock, err := lock(path)
	if err != nil {
		return Written{}, err
	}
	defer unlock()
	pub := key.Public().(ed25519.PublicKey)
	tip, err := currentTip(path, pub)
	if err != nil {
		return Written{}, err
	}
	if err := setAsideTornLine(path, tip); err != nil {
		return Written{}, err
	}
	if !tip.hasHead {

		if err := writeHead(path, key, 0, Genesis); err != nil {
			return Written{}, err
		}
	}
	r.Version, r.Seq, r.PrevHash = 1, tip.seq+1, tip.hash
	r.KeyID = KeyID(pub)
	if r.Timestamp == "" {
		r.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	body, err := signingBytes(r)
	if err != nil {
		return Written{}, err
	}
	r.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, body))
	line, err := json.Marshal(r)
	if err != nil {
		return Written{}, fmt.Errorf("encode evidence record: %w", err)
	}
	if err := appendLine(path, line); err != nil {
		return Written{}, err
	}
	hash := LineHash(line)
	if err := writeHead(path, key, r.Seq, hash); err != nil {
		return Written{}, err
	}
	return Written{Seq: r.Seq, Hash: hash, PrevHash: tip.hash, KeyID: r.KeyID, OtherKeys: tip.otherKeys}, nil
}

func appendLine(path string, line []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("open evidence log: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		_ = f.Close()
		return fmt.Errorf("append to evidence log: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("sync evidence log: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close evidence log: %w", err)
	}
	return nil
}

func writeHead(path string, key ed25519.PrivateKey, seq uint64, hash string) error {
	h := head{Seq: seq, Hash: hash, KeyID: KeyID(key.Public().(ed25519.PublicKey))}
	h.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, h.signedBytes()))
	b, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("encode evidence head: %w", err)
	}
	if err := obs.ReplaceFile(HeadPath(path), append(b, '\n'), 0o640); err != nil {
		return fmt.Errorf("write evidence head: %w", err)
	}
	return nil
}

type logFile struct {
	lines [][]byte
	torn  []byte
}

func readLog(path string) (logFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return logFile{}, err
	}
	var l logFile
	for len(b) > 0 {
		line, rest, complete := bytes.Cut(b, []byte("\n"))
		if !complete {
			l.torn = line
			break
		}
		l.lines = append(l.lines, line)
		b = rest
	}
	return l, nil
}

type tip struct {
	seq       uint64
	hash      string
	torn      []byte
	size      int64
	hasHead   bool
	otherKeys int
}

func currentTip(path string, pub ed25519.PublicKey) (tip, error) {
	h, headErr := readHead(path)
	if headErr != nil && !errors.Is(headErr, os.ErrNotExist) {
		return tip{}, headErr
	}
	hasHead := headErr == nil
	log, err := readLog(path)
	if errors.Is(err, os.ErrNotExist) {
		if hasHead && h.Seq > 0 {
			return tip{}, errors.New("the evidence log is missing but its head file exists; the log may have been deleted")
		}
		return tip{hash: Genesis, hasHead: hasHead}, nil
	}
	if err != nil {
		return tip{}, fmt.Errorf("read evidence log: %w", err)
	}
	t := tip{hash: Genesis, torn: log.torn, hasHead: hasHead}
	known := map[string]ed25519.PublicKey{KeyID(pub): pub}
	headHash := Genesis
	for i, line := range log.lines {
		var r Record
		if err := json.Unmarshal(line, &r); err != nil {
			return tip{}, fmt.Errorf("the evidence log is damaged, refusing to append: line %d: %w", i+1, err)
		}
		if _, mine := known[r.KeyID]; mine {
			if err := verifyLine(i+1, line, t.seq, t.hash, known); err != nil {
				return tip{}, fmt.Errorf("the evidence log is damaged, refusing to append: %w", err)
			}
		} else {
			if r.Seq != t.seq+1 || r.PrevHash != t.hash {
				return tip{}, fmt.Errorf("the evidence log is damaged, refusing to append: line %d does not follow the record before it", i+1)
			}
			t.otherKeys++
		}
		t.seq, t.hash = r.Seq, LineHash(line)
		if hasHead && t.seq == h.Seq {
			headHash = t.hash
		}
		t.size += int64(len(line)) + 1
	}
	switch {
	case !hasHead && t.seq > 0:
		return tip{}, errors.New("the evidence log has records but its head file is missing, refusing to append")
	case hasHead && h.Seq > t.seq:
		return tip{}, fmt.Errorf("the evidence log ends at record %d but its head file says %d, refusing to append", t.seq, h.Seq)
	case hasHead && h.Hash != headHash:
		return tip{}, fmt.Errorf("record %d differs from the one the head file names, refusing to append", h.Seq)
	}
	return t, nil
}

func setAsideTornLine(path string, t tip) error {
	if len(t.torn) == 0 {
		return nil
	}
	aside := fmt.Sprintf("%s.torn-%d", path, time.Now().UnixNano())
	if err := os.WriteFile(aside, t.torn, 0o640); err != nil {
		return fmt.Errorf("keep incomplete evidence line: %w", err)
	}
	if err := os.Truncate(path, t.size); err != nil {
		return fmt.Errorf("remove incomplete evidence line: %w", err)
	}
	return nil
}

func readHead(path string) (head, error) {
	b, err := os.ReadFile(HeadPath(path))
	if err != nil {
		return head{}, err
	}
	var h head
	if err := json.Unmarshal(b, &h); err != nil {
		return head{}, fmt.Errorf("the evidence head file is damaged: %w", err)
	}
	return h, nil
}

type VerifyOptions struct {
	HeadOptional bool

	MinSeq uint64
}

type VerifyResult struct {
	Records  uint64
	LastHash string
	Warnings []string
}

func Verify(logPath, headPath string, keys []ed25519.PublicKey, opts VerifyOptions) (VerifyResult, error) {
	known := map[string]ed25519.PublicKey{}
	for _, k := range keys {
		known[KeyID(k)] = k
	}
	log, err := readLog(logPath)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("open evidence log: %w", err)
	}
	var res VerifyResult
	prev := Genesis
	hashes := make([]string, 0, len(log.lines))
	for i, line := range log.lines {
		if err := verifyLine(i+1, line, res.Records, prev, known); err != nil {
			return VerifyResult{}, err
		}
		res.Records++
		prev = LineHash(line)
		hashes = append(hashes, prev)
	}
	res.LastHash = prev
	if res.Records == 0 {
		return VerifyResult{}, errors.New("the log is empty; records may have been deleted")
	}
	if len(log.torn) > 0 {
		res.Warnings = append(res.Warnings, "the log ends in an incomplete line, left by an interrupted write; it is unsigned and was not counted")
	}
	if err := verifyHead(headPath, known, hashes, opts, &res); err != nil {
		return VerifyResult{}, err
	}
	if res.Records < opts.MinSeq {
		return VerifyResult{}, fmt.Errorf("the log ends at record %d, but record %d is known to exist; records were deleted", res.Records, opts.MinSeq)
	}
	return res, nil
}

func verifyLine(n int, line []byte, count uint64, prev string, known map[string]ed25519.PublicKey) error {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var r Record
	if err := dec.Decode(&r); err != nil {
		return fmt.Errorf("line %d: not a valid record: %w", n, err)
	}
	if r.Seq != count+1 {
		return fmt.Errorf("line %d: sequence %d where %d was expected; a record was removed or reordered", n, r.Seq, count+1)
	}
	if r.PrevHash != prev {
		return fmt.Errorf("line %d: prev_hash does not match the record before it; a record was edited, removed or reordered", n)
	}
	key, ok := known[r.KeyID]
	if !ok {
		return fmt.Errorf("line %d: signed by key %s, which was not supplied", n, r.KeyID)
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return fmt.Errorf("line %d: unreadable signature", n)
	}
	body, err := signingBytes(r)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, body, sig) {
		return fmt.Errorf("line %d: the signature does not match; the record was edited", n)
	}
	canonical, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("line %d: %w", n, err)
	}
	if !bytes.Equal(canonical, line) {
		return fmt.Errorf("line %d: the bytes differ from what was signed; the record was edited", n)
	}
	return nil
}

func verifyHead(headPath string, known map[string]ed25519.PublicKey, hashes []string, opts VerifyOptions, res *VerifyResult) error {
	b, err := os.ReadFile(headPath)
	if errors.Is(err, os.ErrNotExist) {
		if opts.HeadOptional {
			res.Warnings = append(res.Warnings, "no head file was checked, so removal of the newest records would not be detected")
			return nil
		}
		return errors.New("the head file is missing; removal of the newest records cannot be ruled out")
	}
	if err != nil {
		return fmt.Errorf("read head file: %w", err)
	}
	var h head
	if err := json.Unmarshal(b, &h); err != nil {
		return fmt.Errorf("the head file is damaged: %w", err)
	}
	key, ok := known[h.KeyID]
	if !ok {
		return fmt.Errorf("the head file is signed by key %s, which was not supplied", h.KeyID)
	}
	sig, err := base64.StdEncoding.DecodeString(h.Signature)
	if err != nil || !ed25519.Verify(key, h.signedBytes(), sig) {
		return errors.New("the head file's signature does not match")
	}
	if h.Seq > res.Records {
		return fmt.Errorf("the log ends at record %d, but the signed head says %d; records were deleted", res.Records, h.Seq)
	}
	if h.Seq > 0 && h.Hash != hashes[h.Seq-1] {
		return fmt.Errorf("record %d differs from the one the signed head names", h.Seq)
	}
	if h.Seq < res.Records {
		res.Warnings = append(res.Warnings, fmt.Sprintf("the head file names record %d of %d; this happens when a drill is interrupted just after signing, and the next drill brings it up to date", h.Seq, res.Records))
	}
	return nil
}

func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

func GenerateKey(path string) (pubPath string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("encode private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("encode public key: %w", err)
	}
	pubPath = path + ".pub"
	if _, err := os.Stat(pubPath); err == nil {
		return "", fmt.Errorf("%s already exists", pubPath)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create private key: %w", err)
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write private key: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}
	if err := restrictKey(path); err != nil {
		return "", err
	}
	if err := os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644); err != nil { //nolint:gosec
		return "", fmt.Errorf("write public key: %w", err)
	}
	return pubPath, nil
}

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	if err := checkKeyAccess(path); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s is not a PEM key; create one with pol evidence keygen", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s is not a private key: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an ed25519 key", path)
	}
	return priv, nil
}

func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("%s is not a PEM key", path)
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s is not a public key: %w", path, err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an ed25519 key", path)
	}
	return pub, nil
}
