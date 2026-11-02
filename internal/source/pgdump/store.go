package pgdump

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/almera-vs/proof-of-life/internal/config"
)

const tocFile = "toc.dat"

type entry struct {
	name    string
	modTime time.Time
	size    int64
	isDir   bool
}

type store interface {
	list(ctx context.Context) ([]entry, error)

	head(ctx context.Context, e entry) (io.ReadCloser, error)

	writeTar(ctx context.Context, e entry, dest string, w *tar.Writer) error
}

func newStore(repo config.Repo) (store, error) {
	if repo.Type == "posix" {
		return localStore{root: repo.Path}, nil
	}
	return newS3Store(repo)
}

func matches(pattern, name string) bool {
	if pattern == "" {
		return true
	}
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}

func newest(entries []entry, pattern string) (entry, bool) {
	var best entry
	found := false
	for _, e := range entries {
		if !matches(pattern, e.name) {
			continue
		}
		if !found || e.modTime.After(best.modTime) || (e.modTime.Equal(best.modTime) && e.name > best.name) {
			best, found = e, true
		}
	}
	return best, found
}

type localStore struct{ root string }

func (l localStore) list(context.Context) ([]entry, error) {
	items, err := os.ReadDir(l.root)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", l.root, err)
	}
	var out []entry
	for _, it := range items {
		info, err := it.Info()
		if err != nil {
			return nil, fmt.Errorf("stat %s: %w", it.Name(), err)
		}
		if it.IsDir() {
			toc, err := os.Stat(filepath.Join(l.root, it.Name(), tocFile))
			if err != nil {
				continue
			}
			size, err := dirSize(filepath.Join(l.root, it.Name()))
			if err != nil {
				return nil, err
			}
			out = append(out, entry{name: it.Name(), modTime: toc.ModTime(), size: size, isDir: true})
			continue
		}
		out = append(out, entry{name: it.Name(), modTime: info.ModTime(), size: info.Size()})
	}
	return out, nil
}

func dirSize(dir string) (int64, error) {
	items, err := os.ReadDir(dir)
	if err != nil {
		return 0, fmt.Errorf("list %s: %w", dir, err)
	}
	var total int64
	for _, it := range items {
		info, err := it.Info()
		if err != nil {
			return 0, fmt.Errorf("stat %s: %w", it.Name(), err)
		}
		total += info.Size()
	}
	return total, nil
}

func (l localStore) head(_ context.Context, e entry) (io.ReadCloser, error) {
	p := filepath.Join(l.root, e.name)
	if e.isDir {
		p = filepath.Join(p, tocFile)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, fmt.Errorf("open archive: %w", err)
	}
	return f, nil
}

func (l localStore) writeTar(_ context.Context, e entry, dest string, w *tar.Writer) error {
	src := filepath.Join(l.root, e.name)
	if !e.isDir {
		return tarFile(w, src, dest)
	}
	items, err := os.ReadDir(src)
	if err != nil {
		return fmt.Errorf("list archive: %w", err)
	}
	if err := w.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: dest + "/", Mode: 0o700, Uid: 999, Gid: 999, ModTime: time.Now()}); err != nil {
		return fmt.Errorf("write tar: %w", err)
	}
	for _, it := range items {
		if err := tarFile(w, filepath.Join(src, it.Name()), dest+"/"+it.Name()); err != nil {
			return err
		}
	}
	return nil
}

func tarFile(w *tar.Writer, src, name string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open archive file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat archive file: %w", err)
	}
	return tarStream(w, name, info.Size(), info.ModTime(), f)
}

func tarStream(w *tar.Writer, name string, size int64, mod time.Time, r io.Reader) error {
	if err := w.WriteHeader(&tar.Header{Name: name, Size: size, Mode: 0o600, Uid: 999, Gid: 999, ModTime: mod}); err != nil {
		return fmt.Errorf("write tar header: %w", err)
	}
	if _, err := io.Copy(w, r); err != nil {
		return fmt.Errorf("stream archive into sandbox: %w", err)
	}
	return nil
}

type s3Store struct {
	client *minio.Client
	bucket string
	prefix string
}

func newS3Store(repo config.Repo) (store, error) {
	creds, err := s3Credentials(repo.Credentials)
	if err != nil {
		return nil, err
	}
	endpoint := repo.Endpoint
	if endpoint == "" {
		endpoint = "s3." + repo.Region + ".amazonaws.com"
	}
	if repo.Port != 0 {
		endpoint = fmt.Sprintf("%s:%d", endpoint, repo.Port)
	}
	lookup := minio.BucketLookupDNS
	if repo.URIStyle == "path" {
		lookup = minio.BucketLookupPath
	}
	opts := &minio.Options{Creds: creds, Secure: true, Region: repo.Region, BucketLookup: lookup}
	if repo.VerifyTLS != nil && !*repo.VerifyTLS {
		tr, err := minio.DefaultTransport(true)
		if err != nil {
			return nil, fmt.Errorf("configure s3 transport: %w", err)
		}
		tr.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec
		opts.Transport = tr
	}
	c, err := minio.New(endpoint, opts)
	if err != nil {
		return nil, fmt.Errorf("configure s3 client: %w", err)
	}
	prefix := strings.TrimPrefix(repo.Path, "/")
	if prefix != "" && !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	return &s3Store{client: c, bucket: repo.Bucket, prefix: prefix}, nil
}

func s3Credentials(c config.Credentials) (*credentials.Credentials, error) {
	if c.FromEnv {
		return credentials.NewEnvAWS(), nil
	}
	key, err := c.AccessKey.Resolve()
	if err != nil {
		return nil, fmt.Errorf("source.repo.credentials.access_key: %w", err)
	}
	secret, err := c.SecretKey.Resolve()
	if err != nil {
		return nil, fmt.Errorf("source.repo.credentials.secret_key: %w", err)
	}
	return credentials.NewStaticV4(key.Reveal(), secret.Reveal(), ""), nil
}

func (s *s3Store) list(ctx context.Context) ([]entry, error) {
	byName := map[string]*entry{}
	var dirs []string
	for o := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: s.prefix, Recursive: true}) {
		if o.Err != nil {
			return nil, fmt.Errorf("list s3 objects: %w", o.Err)
		}
		rel := strings.TrimPrefix(o.Key, s.prefix)
		if !safeName(rel) {
			return nil, fmt.Errorf("object %q has a name that could escape the archive directory, refusing to read it", o.Key)
		}
		name, rest, nested := strings.Cut(rel, "/")
		e := byName[name]
		if e == nil {
			e = &entry{name: name, isDir: nested}
			byName[name] = e
		}
		e.size += o.Size
		if !nested || rest == tocFile {
			e.modTime = o.LastModified
		}
		if nested && rest == tocFile {
			dirs = append(dirs, name)
		}
	}
	out := make([]entry, 0, len(byName))
	for _, e := range byName {
		if e.isDir && !slices.Contains(dirs, e.name) {
			continue
		}
		out = append(out, *e)
	}
	return out, nil
}

func (s *s3Store) head(ctx context.Context, e entry) (io.ReadCloser, error) {
	key := s.prefix + e.name
	if e.isDir {
		key += "/" + tocFile
	}
	o, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("open s3 object: %w", err)
	}
	return o, nil
}

func (s *s3Store) writeTar(ctx context.Context, e entry, dest string, w *tar.Writer) error {
	if !e.isDir {
		return s.tarObject(ctx, s.prefix+e.name, dest, w)
	}
	if err := w.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: dest + "/", Mode: 0o700, Uid: 999, Gid: 999, ModTime: time.Now()}); err != nil {
		return fmt.Errorf("write tar: %w", err)
	}
	dirPrefix := s.prefix + e.name + "/"
	for o := range s.client.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: dirPrefix, Recursive: true}) {
		if o.Err != nil {
			return fmt.Errorf("list s3 objects: %w", o.Err)
		}
		rel := strings.TrimPrefix(o.Key, dirPrefix)
		if !safeName(rel) {
			return fmt.Errorf("object %q has a name that could escape the archive directory, refusing to read it", o.Key)
		}
		if err := s.tarObject(ctx, o.Key, dest+"/"+rel, w); err != nil {
			return err
		}
	}
	return nil
}

func (s *s3Store) tarObject(ctx context.Context, key, name string, w *tar.Writer) error {
	o, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return fmt.Errorf("open s3 object: %w", err)
	}
	defer o.Close()
	info, err := o.Stat()
	if err != nil {
		return fmt.Errorf("stat s3 object: %w", err)
	}
	return tarStream(w, name, info.Size, info.LastModified, o)
}

func safeName(rel string) bool {
	if rel == "" || strings.HasPrefix(rel, "/") || strings.Contains(rel, `\`) {
		return false
	}
	for part := range strings.SplitSeq(rel, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func isConnectivity(err error) bool {
	var resp minio.ErrorResponse
	return !errors.As(err, &resp) && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, ErrNotArchive)
}
