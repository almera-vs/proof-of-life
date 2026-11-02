package docker

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/almera-vs/proof-of-life/internal/sandbox"
)

const runUser = "999:999"

const cleanupTimeout = 2 * time.Minute

const settlePasses = 4

type Sandbox struct {
	client *Client

	RestoreNetwork string
	mu             sync.Mutex
	pulled         map[string]bool
}

func New(restoreNetwork string) (*Sandbox, error) {
	c, err := NewClient()
	if err != nil {
		return nil, err
	}
	return &Sandbox{client: c, RestoreNetwork: restoreNetwork, pulled: map[string]bool{}}, nil
}

func (s *Sandbox) Ping(ctx context.Context) error { return s.client.Ping(ctx) }

func (s *Sandbox) Create(ctx context.Context, spec sandbox.Spec) (sandbox.Instance, error) {
	if err := s.ensureImage(ctx, spec.Image, spec.Dockerfile); err != nil {
		return nil, err
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	in := &instance{s: s, id: id, spec: spec, labels: labels(spec.RunID, id)}
	in.volume = "pol-" + spec.RunID + "-" + id
	body := map[string]any{"Name": in.volume, "Labels": in.labels}
	if err := s.client.json(ctx, http.MethodPost, "/volumes/create", nil, body, nil); err != nil {
		_ = s.Destroy(ctx, id)
		return nil, fmt.Errorf("create sandbox volume: %w", err)
	}
	return in, nil
}

func (s *Sandbox) Destroy(ctx context.Context, id string) error {
	return s.remove(ctx, sandbox.LabelSandbox+"="+id, "-"+id, ctx.Err() != nil)
}

func (s *Sandbox) remove(ctx context.Context, label, volumeName string, settle bool) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	var err error
	clean := 0
	for range 20 {
		err = s.sweep(ctx, label, volumeName)
		if err == nil {
			clean++
			if !settle || clean == settlePasses {
				return nil
			}
		} else {
			clean = 0
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(time.Second):
		}
	}
	return err
}

func (s *Sandbox) sweep(ctx context.Context, label, volumeName string) error {
	var errs []error
	containers, err := s.client.listContainers(ctx, label)
	if err != nil {
		errs = append(errs, fmt.Errorf("list sandbox containers: %w", err))
	}
	for _, c := range containers {
		if err := s.client.removeContainer(ctx, c.ID); err != nil {
			errs = append(errs, fmt.Errorf("remove container %s: %w", c.ID[:12], err))
		}
	}
	volumes, err := s.client.listVolumes(ctx, label)
	if err != nil {
		errs = append(errs, fmt.Errorf("list sandbox volumes: %w", err))
	}
	named, err := s.client.listVolumesNamed(ctx, volumeName)
	if err != nil {
		errs = append(errs, fmt.Errorf("list sandbox volumes: %w", err))
	}
	for _, v := range append(volumes, named...) {
		if err := s.client.removeVolume(ctx, v.Name); err != nil {
			errs = append(errs, fmt.Errorf("remove volume %s: %w", v.Name, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Sandbox) Keep(ctx context.Context, runID, id string) error {
	ls := labels(runID, id)
	ls[sandbox.LabelKeep] = "true"
	body := map[string]any{"Name": "pol-keep-" + runID + "-" + id, "Labels": ls}
	if err := s.client.json(ctx, http.MethodPost, "/volumes/create", nil, body, nil); err != nil {
		return fmt.Errorf("mark sandbox as kept: %w", err)
	}
	return nil
}

type GCOptions struct {
	IncludeKept bool

	DryRun bool
}

type GCResult struct {
	Runs       []string
	Containers int
	Volumes    int
	Skipped    []string
}

func (s *Sandbox) Collect(ctx context.Context, opts GCOptions) (GCResult, error) {
	var res GCResult
	containers, err := s.client.listContainers(ctx, sandbox.LabelRunID)
	if err != nil {
		return res, fmt.Errorf("list containers: %w", err)
	}
	volumes, err := s.client.listVolumes(ctx, sandbox.LabelRunID)
	if err != nil {
		return res, fmt.Errorf("list volumes: %w", err)
	}
	runs := map[string]map[string]string{}
	kept := map[string]bool{}
	for _, c := range containers {
		runs[c.Labels[sandbox.LabelRunID]] = c.Labels
		kept[c.Labels[sandbox.LabelRunID]] = kept[c.Labels[sandbox.LabelRunID]] || c.Labels[sandbox.LabelKeep] == "true"
	}
	for _, v := range volumes {
		runs[v.Labels[sandbox.LabelRunID]] = v.Labels
		kept[v.Labels[sandbox.LabelRunID]] = kept[v.Labels[sandbox.LabelRunID]] || v.Labels[sandbox.LabelKeep] == "true"
	}
	var errs []error
	for run, ls := range runs {
		switch {
		case !opts.IncludeKept && processAlive(ls):
			res.Skipped = append(res.Skipped, run+" (drill still running or owned by another host; use --all)")
			continue
		case kept[run] && !opts.IncludeKept:
			res.Skipped = append(res.Skipped, run+" (kept with --keep-sandbox-on-fail; use --all)")
			continue
		}
		res.Runs = append(res.Runs, run)
		for _, c := range containers {
			if c.Labels[sandbox.LabelRunID] == run {
				res.Containers++
			}
		}
		for _, v := range volumes {
			if v.Labels[sandbox.LabelRunID] == run {
				res.Volumes++
			}
		}
		if !opts.DryRun {
			if err := s.remove(ctx, sandbox.LabelRunID+"="+run, "pol-"+run+"-", true); err != nil {
				errs = append(errs, fmt.Errorf("run %s: %w", run, err))
			}
		}
	}
	return res, errors.Join(errs...)
}

func processAlive(ls map[string]string) bool {
	host, _ := os.Hostname()
	if ls[sandbox.LabelHost] != host {
		return true
	}
	pid, err := strconv.Atoi(ls[sandbox.LabelPID])
	if err != nil || pid <= 0 || pid == os.Getpid() {
		return false
	}
	return processExists(pid)
}

func (s *Sandbox) ensureImage(ctx context.Context, ref string, dockerfile []byte) error {
	s.mu.Lock()
	done := s.pulled[ref]
	s.mu.Unlock()
	if done {
		return nil
	}
	have, err := s.client.HasImage(ctx, ref)
	if err != nil {
		return fmt.Errorf("inspect image %s: %w", ref, err)
	}
	if !have {
		pullErr := s.client.PullImage(ctx, ref)
		switch {
		case pullErr == nil:
		case len(dockerfile) > 0:
			if err := s.client.BuildImage(ctx, ref, dockerfile); err != nil {
				return fmt.Errorf("build image %s: %w", ref, err)
			}
		default:
			return fmt.Errorf("pull image %s: %w", ref, pullErr)
		}
	}
	s.mu.Lock()
	s.pulled[ref] = true
	s.mu.Unlock()
	return nil
}

func labels(runID, id string) map[string]string {
	host, _ := os.Hostname()
	return map[string]string{
		sandbox.LabelRunID:   runID,
		sandbox.LabelSandbox: id,
		sandbox.LabelPID:     strconv.Itoa(os.Getpid()),
		sandbox.LabelHost:    host,
	}
}

func newID() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate sandbox id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

type instance struct {
	s      *Sandbox
	id     string
	spec   sandbox.Spec
	labels map[string]string
	volume string
	server string
}

func (in *instance) ID() string { return in.id }

func (in *instance) hostConfig(network string, binds []string) map[string]any {
	if network == "" {
		network = "none"
	}
	mountBinds := append([]string{in.volume + ":" + sandbox.DataMount}, binds...)
	return map[string]any{
		"Binds":          mountBinds,
		"NetworkMode":    network,
		"NanoCpus":       int64(in.spec.CPUs * 1e9),
		"Memory":         in.spec.MemoryBytes,
		"MemorySwap":     in.spec.MemoryBytes,
		"PidsLimit":      1024,
		"ShmSize":        min(in.spec.MemoryBytes/4, 1<<30),
		"ReadonlyRootfs": true,
		"CapDrop":        []string{"ALL"},
		"SecurityOpt":    []string{"no-new-privileges"},
		"Tmpfs": map[string]string{
			"/tmp":            "rw,nosuid,nodev,size=256m,mode=1777",
			sandbox.SocketDir: "rw,nosuid,nodev,size=16m,uid=999,gid=999,mode=0775",
		},
	}
}

func (in *instance) create(ctx context.Context, image string, entrypoint, cmd, env []string, host map[string]any) (string, error) {
	body := map[string]any{
		"Image":      image,
		"User":       runUser,
		"Env":        env,
		"Labels":     in.labels,
		"HostConfig": host,
	}
	if len(entrypoint) > 0 {
		body["Entrypoint"] = entrypoint
	}
	if cmd != nil {
		body["Cmd"] = cmd
	}
	var out struct {
		ID string `json:"Id"`
	}
	if err := in.s.client.json(ctx, http.MethodPost, "/containers/create", nil, body, &out); err != nil {
		return "", fmt.Errorf("create container from %s: %w", image, err)
	}
	return out.ID, nil
}

func (in *instance) start(ctx context.Context, id string) error {
	if err := in.s.client.json(ctx, http.MethodPost, "/containers/"+id+"/start", nil, nil, nil); err != nil {
		return fmt.Errorf("start container: %w", err)
	}
	return nil
}

func (in *instance) RunJob(ctx context.Context, job sandbox.Job) (sandbox.ExecResult, error) {
	image := job.Image
	if image == "" {
		image = in.spec.Image
	}
	network := job.Network
	if network == "restore" {
		network = in.s.RestoreNetwork
	}
	host := in.hostConfig(network, job.Binds)
	if len(job.Groups) > 0 {
		host["GroupAdd"] = job.Groups
	}
	id, err := in.create(ctx, image, []string{"/bin/sh", "-c", `exec "$@"`, "--"}, job.Cmd, job.Env, host)
	if err != nil {
		return sandbox.ExecResult{}, err
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancel()
		_ = in.s.client.removeContainer(cctx, id)
	}()
	if err := in.start(ctx, id); err != nil {
		return sandbox.ExecResult{}, err
	}
	var wait struct {
		StatusCode int `json:"StatusCode"`
	}
	if err := in.s.client.json(ctx, http.MethodPost, "/containers/"+id+"/wait", nil, nil, &wait); err != nil {
		return sandbox.ExecResult{}, fmt.Errorf("wait for job: %w", err)
	}
	stdout, stderr, err := in.logs(ctx, id, "")
	if err != nil {
		return sandbox.ExecResult{}, err
	}
	return sandbox.ExecResult{ExitCode: wait.StatusCode, Stdout: stdout, Stderr: stderr}, nil
}

func (in *instance) logs(ctx context.Context, id, tail string) (string, string, error) {
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}}
	if tail != "" {
		q.Set("tail", tail)
	}
	resp, err := in.s.client.do(ctx, http.MethodGet, "/containers/"+id+"/logs", q, "", nil)
	if err != nil {
		return "", "", fmt.Errorf("read container logs: %w", err)
	}
	defer resp.Body.Close()
	var so, se tailBuffer
	if err := demux(resp.Body, &so, &se); err != nil {
		return "", "", err
	}
	return so.String(), se.String(), nil
}

func (in *instance) CopyIn(ctx context.Context, dir string, tarStream io.Reader) error {
	id, err := in.create(ctx, in.spec.Image, []string{"/bin/true"}, nil, nil, in.hostConfig("", nil))
	if err != nil {
		return err
	}
	defer func() {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
		defer cancel()
		_ = in.s.client.removeContainer(cctx, id)
	}()
	q := url.Values{"path": {dir}}
	resp, err := in.s.client.do(ctx, http.MethodPut, "/containers/"+id+"/archive", q, "application/x-tar", tarStream)
	if err != nil {
		return fmt.Errorf("copy into sandbox: %w", err)
	}
	return resp.Body.Close()
}

func (in *instance) StartServer(ctx context.Context, args []string) error {
	if in.server != "" {
		return errors.New("the sandbox server is already started")
	}
	id, err := in.create(ctx, in.spec.Image, []string{"postgres"}, args, nil, in.hostConfig("none", nil))
	if err != nil {
		return err
	}
	in.server = id
	return in.start(ctx, id)
}

func (in *instance) Exec(ctx context.Context, argv, env []string) (sandbox.ExecResult, error) {
	if in.server == "" {
		return sandbox.ExecResult{}, errors.New("the sandbox server is not started")
	}
	var created struct {
		ID string `json:"Id"`
	}
	body := map[string]any{"AttachStdout": true, "AttachStderr": true, "Cmd": argv, "Env": env, "User": runUser}
	c := in.s.client
	if err := c.json(ctx, http.MethodPost, "/containers/"+in.server+"/exec", nil, body, &created); err != nil {
		return sandbox.ExecResult{}, fmt.Errorf("create exec: %w", err)
	}
	resp, err := c.do(ctx, http.MethodPost, "/exec/"+created.ID+"/start", nil, "application/json", strings.NewReader(`{"Detach":false,"Tty":false}`))
	if err != nil {
		return sandbox.ExecResult{}, fmt.Errorf("start exec: %w", err)
	}
	defer resp.Body.Close()
	var so, se tailBuffer
	if err := demux(resp.Body, &so, &se); err != nil {
		return sandbox.ExecResult{}, err
	}
	var state struct {
		ExitCode int  `json:"ExitCode"`
		Running  bool `json:"Running"`
	}
	if err := c.json(ctx, http.MethodGet, "/exec/"+created.ID+"/json", nil, nil, &state); err != nil {
		return sandbox.ExecResult{}, fmt.Errorf("inspect exec: %w", err)
	}
	if state.Running {
		return sandbox.ExecResult{}, errors.New("exec stream ended while the command was still running")
	}
	return sandbox.ExecResult{ExitCode: state.ExitCode, Stdout: so.String(), Stderr: se.String()}, nil
}

func (in *instance) ServerRunning(ctx context.Context) (bool, error) {
	if in.server == "" {
		return false, nil
	}
	var st struct {
		State struct {
			Running bool `json:"Running"`
		} `json:"State"`
	}
	if err := in.s.client.json(ctx, http.MethodGet, "/containers/"+in.server+"/json", nil, nil, &st); err != nil {
		return false, fmt.Errorf("inspect server: %w", err)
	}
	return st.State.Running, nil
}

func (in *instance) ServerLogs(ctx context.Context) (string, error) {
	if in.server == "" {
		return "", nil
	}
	so, se, err := in.logs(ctx, in.server, "")
	return so + se, err
}

func writeTarFile(w io.Writer, name string, data []byte) error {
	tw := tar.NewWriter(w)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: time.Now()}); err != nil {
		return fmt.Errorf("write tar header: %w", err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("write tar body: %w", err)
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("close tar: %w", err)
	}
	return nil
}

func (s *Sandbox) EnsureImage(ctx context.Context, ref string, dockerfile []byte) error {
	return s.ensureImage(ctx, ref, dockerfile)
}
