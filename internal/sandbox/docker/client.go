package docker

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
)

const apiVersion = "v1.44"

const maxCapture = 8 << 20

type Client struct {
	http *http.Client
	base string
}

func NewClient() (*Client, error) {
	host := os.Getenv("DOCKER_HOST")
	if host == "" {
		host = defaultHost
	}
	return newClient(host)
}

func newClient(host string) (*Client, error) {
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("parse DOCKER_HOST: %w", err)
	}
	local := func(dial func(ctx context.Context) (net.Conn, error)) *Client {
		tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) }}
		return &Client{http: &http.Client{Transport: tr}, base: "http://docker/" + apiVersion}
	}
	switch u.Scheme {
	case "unix":
		return local(func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", u.Path)
		}), nil
	case "npipe":
		pipe := strings.ReplaceAll(u.Path, "/", `\`)
		return local(func(ctx context.Context) (net.Conn, error) { return dialPipe(ctx, pipe) }), nil
	case "tcp", "http":

		if !isLoopback(u.Hostname()) {
			return nil, fmt.Errorf("DOCKER_HOST %s is a remote daemon over unencrypted TCP; use the local socket, or forward it to 127.0.0.1 over SSH", u.Host)
		}
		return &Client{http: &http.Client{}, base: "http://" + u.Host + "/" + apiVersion}, nil
	}
	return nil, fmt.Errorf("unsupported DOCKER_HOST scheme %q", u.Scheme)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func IsNotFound(err error) bool {
	var e *apiError
	return errors.As(err, &e) && e.status == http.StatusNotFound
}

type apiError struct {
	status  int
	message string
}

func (e *apiError) Error() string { return fmt.Sprintf("docker api: %d: %s", e.status, e.message) }

func (c *Client) do(ctx context.Context, method, path string, q url.Values, contentType string, body io.Reader) (*http.Response, error) {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, fmt.Errorf("build docker request: %w", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if errors.Is(err, syscall.EACCES) {
			return nil, fmt.Errorf("this user cannot open the Docker socket; add it to the group that owns the socket (docker run --group-add <gid>): %w", err)
		}
		return nil, fmt.Errorf("docker api %s %s: %w", method, path, err)
	}
	if resp.StatusCode >= 300 && resp.StatusCode != http.StatusNotModified {
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		var m struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(b, &m) != nil || m.Message == "" {
			m.Message = strings.TrimSpace(string(b))
		}
		return nil, &apiError{status: resp.StatusCode, message: m.Message}
	}
	return resp, nil
}

func (c *Client) json(ctx context.Context, method, path string, q url.Values, in, out any) error {
	var body io.Reader
	ct := ""
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode docker request: %w", err)
		}
		body, ct = bytes.NewReader(b), "application/json"
	}
	resp, err := c.do(ctx, method, path, q, ct, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode docker response for %s: %w", path, err)
	}
	return nil
}

func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, "/_ping", nil, "", nil)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Client) HasImage(ctx context.Context, ref string) (bool, error) {
	err := c.json(ctx, http.MethodGet, "/images/"+ref+"/json", nil, nil, nil)
	if IsNotFound(err) {
		return false, nil
	}
	return err == nil, err
}

func (c *Client) PullImage(ctx context.Context, ref string) error {
	name, tag := ref, "latest"
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		name, tag = ref[:i], ref[i+1:]
	}
	q := url.Values{"fromImage": {name}, "tag": {tag}}
	resp, err := c.do(ctx, http.MethodPost, "/images/create", q, "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return streamError(resp.Body)
}

func (c *Client) BuildImage(ctx context.Context, ref string, dockerfile []byte) error {
	var ctxTar bytes.Buffer
	if err := writeTarFile(&ctxTar, "Dockerfile", dockerfile); err != nil {
		return err
	}
	q := url.Values{"t": {ref}, "rm": {"1"}, "forcerm": {"1"}}
	resp, err := c.do(ctx, http.MethodPost, "/build", q, "application/x-tar", &ctxTar)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return streamError(resp.Body)
}

func streamError(r io.Reader) error {
	dec := json.NewDecoder(r)
	for {
		var m struct {
			Error string `json:"error"`
		}
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read docker progress: %w", err)
		}
		if m.Error != "" {
			return errors.New(m.Error)
		}
	}
}

func demux(r io.Reader, stdout, stderr io.Writer) error {
	var hdr [8]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return fmt.Errorf("read docker stream: %w", err)
		}
		w := stdout
		if hdr[0] == 2 {
			w = stderr
		}
		if _, err := io.CopyN(w, r, int64(binary.BigEndian.Uint32(hdr[4:]))); err != nil {
			return fmt.Errorf("read docker stream: %w", err)
		}
	}
}

type tailBuffer struct{ b []byte }

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.b = append(t.b, p...)
	if len(t.b) > maxCapture {
		t.b = t.b[len(t.b)-maxCapture:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string { return string(t.b) }

func labelFilter(labels ...string) url.Values {
	f, _ := json.Marshal(map[string][]string{"label": labels})
	return url.Values{"filters": {string(f)}}
}

type containerSummary struct {
	ID     string            `json:"Id"`
	Labels map[string]string `json:"Labels"`
}

func (c *Client) listContainers(ctx context.Context, labels ...string) ([]containerSummary, error) {
	q := labelFilter(labels...)
	q.Set("all", "1")
	var out []containerSummary
	err := c.json(ctx, http.MethodGet, "/containers/json", q, nil, &out)
	return out, err
}

type volumeSummary struct {
	Name   string            `json:"Name"`
	Labels map[string]string `json:"Labels"`
}

func (c *Client) listVolumes(ctx context.Context, labels ...string) ([]volumeSummary, error) {
	var out struct {
		Volumes []volumeSummary `json:"Volumes"`
	}
	err := c.json(ctx, http.MethodGet, "/volumes", labelFilter(labels...), nil, &out)
	return out.Volumes, err
}

func (c *Client) listVolumesNamed(ctx context.Context, part string) ([]volumeSummary, error) {
	f, err := json.Marshal(map[string][]string{"name": {part}})
	if err != nil {
		return nil, fmt.Errorf("encode volume filter: %w", err)
	}
	var out struct {
		Volumes []volumeSummary `json:"Volumes"`
	}
	if err := c.json(ctx, http.MethodGet, "/volumes", url.Values{"filters": {string(f)}}, nil, &out); err != nil {
		return nil, err
	}
	var matched []volumeSummary
	for _, v := range out.Volumes {
		if strings.HasPrefix(v.Name, "pol-") && strings.Contains(v.Name, part) {
			matched = append(matched, v)
		}
	}
	return matched, nil
}

func (c *Client) removeContainer(ctx context.Context, id string) error {
	err := c.json(ctx, http.MethodDelete, "/containers/"+id, url.Values{"force": {"1"}, "v": {"1"}}, nil, nil)
	if IsNotFound(err) {
		return nil
	}
	var e *apiError
	if errors.As(err, &e) && e.status == http.StatusConflict {
		return nil
	}
	return err
}

func (c *Client) removeVolume(ctx context.Context, name string) error {
	err := c.json(ctx, http.MethodDelete, "/volumes/"+name, url.Values{"force": {"1"}}, nil, nil)
	if IsNotFound(err) {
		return nil
	}
	return err
}
