package notify

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/almera-vs/proof-of-life/internal/config"
	"github.com/almera-vs/proof-of-life/internal/report"
)

func sample() *report.Report {
	return &report.Report{
		RunID: "r1", Drill: "billing", Status: "fail", Title: "Not restorable.",
		Summary:   "The backup could not be proven restorable.",
		Counts:    report.Counts{Passed: 3, Failed: 1},
		RTO:       report.RTO{Text: "Not reached", TargetText: "30m"},
		Attention: []report.Check{{ID: "recovery.wal_continuity", Status: "fail", Reason: "The WAL archive has a gap."}},
	}
}

func TestBuildWordsTheMessage(t *testing.T) {
	m := Build(sample(), "/var/lib/pol/reports/r1.html")
	if m.Subject != "billing: Not restorable" {
		t.Errorf("%q", m.Subject)
	}
	for _, want := range []string{"recovery.wal_continuity: The WAL archive has a gap.", "Measured RTO: Not reached of 30m", "r1.html"} {
		if !strings.Contains(m.Text, want) {
			t.Errorf("missing %q in %s", want, m.Text)
		}
	}
	if strings.Contains(m.Text, "!") {
		t.Error("the tone rules out exclamation marks")
	}
}

func TestWanted(t *testing.T) {
	cfg := config.Notify{On: []string{"fail", "warn"}}
	if !Wanted(cfg, "fail") || Wanted(cfg, "pass") {
		t.Fatal("gating is wrong")
	}
}

func TestWebhookAndSlackDelivery(t *testing.T) {
	var got []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			t.Error(err)
		}
		got = append(got, m)
	}))
	defer srv.Close()
	t.Setenv("POL_T_URL", srv.URL)
	cfg := config.Notify{
		Webhook: &config.Webhook{URL: config.SecretRef{Env: "POL_T_URL"}},
		Slack:   &config.Slack{Webhook: config.SecretRef{Env: "POL_T_URL"}},
	}
	if err := Send(context.Background(), cfg, Build(sample(), "")); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d deliveries", len(got))
	}
	if got[0]["status"] != "fail" || got[0]["run_id"] != "r1" {
		t.Errorf("%+v", got[0])
	}
	if !strings.HasPrefix(got[1]["text"].(string), "*billing: Not restorable*") {
		t.Errorf("%+v", got[1])
	}
}

func TestFailureIsReportedWithoutLeakingTheURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	t.Setenv("POL_T_URL", srv.URL+"/services/T000/B000/secrettoken")
	err := Send(context.Background(), config.Notify{Slack: &config.Slack{Webhook: config.SecretRef{Env: "POL_T_URL"}}}, Build(sample(), ""))
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "secrettoken") {
		t.Fatalf("leaked the webhook URL: %v", err)
	}
}

func TestRetriesServerErrors(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
		}
	}))
	defer srv.Close()
	if err := post(context.Background(), srv.URL, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestSMTPDelivery(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		received <- fakeSMTP(conn)
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	cfg := config.Notify{SMTP: &config.SMTP{Host: "127.0.0.1", Port: port, From: "pol@example.com", To: []string{"dba@example.com"}}}
	if err := Send(context.Background(), cfg, Build(sample(), "")); err != nil {
		t.Fatal(err)
	}
	msg := <-received
	for _, want := range []string{"Subject: billing: Not restorable", "To: dba@example.com", "recovery.wal_continuity"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in %s", want, msg)
		}
	}
	_ = strconv.Itoa(port)
}

func TestMailHeadersCannotBeInjected(t *testing.T) {
	m := Message{Subject: "x\r\nBcc: evil@example.com", Text: "body"}
	got := string(formatMail(config.SMTP{From: "a@b", To: []string{"c@d"}}, m))
	if strings.Contains(got, "\r\nBcc:") {
		t.Fatalf("header injection: %q", got)
	}
}

func fakeSMTP(conn net.Conn) string {
	r := bufio.NewReader(conn)
	say := func(s string) { _, _ = io.WriteString(conn, s+"\r\n") }
	say("220 test")
	var data strings.Builder
	inData := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return data.String()
		}
		if inData {
			if line == ".\r\n" {
				inData = false
				say("250 ok")
				continue
			}
			data.WriteString(line)
			continue
		}
		switch strings.ToUpper(strings.Fields(line)[0]) {
		case "EHLO", "HELO":
			say("250 test")
		case "DATA":
			inData = true
			say("354 go")
		case "QUIT":
			say("221 bye")
			return data.String()
		default:
			say("250 ok")
		}
	}
}

func TestPlaintextOnlyWhenAllowedOrLocal(t *testing.T) {
	cases := []struct {
		cfg  config.SMTP
		want bool
	}{
		{config.SMTP{Host: "smtp.example.com"}, false},
		{config.SMTP{Host: "10.0.0.9"}, false},
		{config.SMTP{Host: "smtp.example.com", AllowPlaintext: true}, true},
		{config.SMTP{Host: "localhost"}, true},
		{config.SMTP{Host: "127.0.0.1"}, true},
	}
	for _, c := range cases {
		if got := plaintextAllowed(c.cfg); got != c.want {
			t.Errorf("%+v: got %v", c.cfg, got)
		}
	}
}
