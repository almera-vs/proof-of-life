package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/smtp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/almera-vs/proof-of-life/internal/config"
	"github.com/almera-vs/proof-of-life/internal/report"
)

const (
	sendTimeout = 30 * time.Second
	attempts    = 3
)

type Message struct {
	Subject string
	Text    string
	Report  *report.Report
}

func Build(r *report.Report, htmlPath string) Message {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", r.Summary)
	if len(r.Attention) > 0 {
		for _, c := range r.Attention {
			fmt.Fprintf(&b, "%s: %s\n", c.ID, c.Reason)
		}
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "%d passed, %d warnings, %d failed, %d not run\n", r.Counts.Passed, r.Counts.Warnings, r.Counts.Failed, r.Counts.Skipped)
	fmt.Fprintf(&b, "Measured RTO: %s of %s\n", r.RTO.Text, r.RTO.TargetText)
	fmt.Fprintf(&b, "Run: %s\n", r.RunID)
	if htmlPath != "" {
		fmt.Fprintf(&b, "Report: %s\n", htmlPath)
	}
	return Message{Subject: r.Drill + ": " + strings.TrimSuffix(r.Title, "."), Text: b.String(), Report: r}
}

func Wanted(cfg config.Notify, status string) bool {
	return slices.Contains(cfg.On, status)
}

func Send(ctx context.Context, cfg config.Notify, m Message) error {
	var errs []error
	if cfg.Webhook != nil {
		errs = append(errs, sendWebhook(ctx, cfg.Webhook.URL, m))
	}
	if cfg.Slack != nil {
		errs = append(errs, sendSlack(ctx, cfg.Slack.Webhook, m))
	}
	if cfg.SMTP != nil {
		errs = append(errs, sendSMTP(ctx, *cfg.SMTP, m))
	}
	return errors.Join(errs...)
}

type webhookPayload struct {
	Subject string        `json:"subject"`
	Text    string        `json:"text"`
	RunID   string        `json:"run_id"`
	Drill   string        `json:"drill"`
	Status  string        `json:"status"`
	Counts  report.Counts `json:"counts"`
	RTO     report.RTO    `json:"rto"`
	Failed  []string      `json:"attention"`
}

func sendWebhook(ctx context.Context, ref config.SecretRef, m Message) error {
	url, err := ref.Resolve()
	if err != nil {
		return fmt.Errorf("notify.webhook.url: %w", err)
	}
	p := webhookPayload{Subject: m.Subject, Text: m.Text, RunID: m.Report.RunID, Drill: m.Report.Drill, Status: m.Report.Status, Counts: m.Report.Counts, RTO: m.Report.RTO, Failed: []string{}}
	for _, c := range m.Report.Attention {
		p.Failed = append(p.Failed, c.ID)
	}
	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("encode webhook payload: %w", err)
	}
	if err := post(ctx, url.Reveal(), body); err != nil {
		return fmt.Errorf("generic webhook: %w", err)
	}
	return nil
}

func sendSlack(ctx context.Context, ref config.SecretRef, m Message) error {
	url, err := ref.Resolve()
	if err != nil {
		return fmt.Errorf("notify.slack.webhook: %w", err)
	}
	body, err := json.Marshal(map[string]string{"text": "*" + m.Subject + "*\n" + m.Text})
	if err != nil {
		return fmt.Errorf("encode slack payload: %w", err)
	}
	if err := post(ctx, url.Reveal(), body); err != nil {
		return fmt.Errorf("slack: %w", err)
	}
	return nil
}

func post(ctx context.Context, url string, body []byte) error {
	client := &http.Client{Timeout: sendTimeout}
	var last error
	for attempt := range attempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return errors.New("cancelled before delivery")
			case <-time.After(time.Duration(attempt) * 2 * time.Second):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return errors.New("the configured URL is invalid")
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			last = errors.New("the request could not be delivered")
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode < 300 {
			return nil
		}
		last = fmt.Errorf("the endpoint answered %d", resp.StatusCode)
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return last
		}
	}
	return last
}

func sendSMTP(ctx context.Context, cfg config.SMTP, m Message) error {
	password := ""
	if cfg.Password != nil {
		p, err := cfg.Password.Resolve()
		if err != nil {
			return fmt.Errorf("notify.smtp.password: %w", err)
		}
		password = p.Reveal()
	}
	if err := deliver(ctx, cfg, password, m); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	return nil
}

func deliver(ctx context.Context, cfg config.SMTP, password string, m Message) error {
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	d := net.Dialer{Timeout: sendTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(sendTimeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return fmt.Errorf("greet: %w", err)
	}
	defer c.Close()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	} else if !plaintextAllowed(cfg) {
		return errors.New("the relay does not offer STARTTLS; set notify.smtp.allow_plaintext to send in the clear")
	}
	if cfg.Username != "" {

		if err := c.Auth(smtp.PlainAuth("", cfg.Username, password, cfg.Host)); err != nil {
			return fmt.Errorf("authenticate: %w", err)
		}
	}
	if err := c.Mail(cfg.From); err != nil {
		return fmt.Errorf("sender: %w", err)
	}
	for _, to := range cfg.To {
		if err := c.Rcpt(to); err != nil {
			return fmt.Errorf("recipient: %w", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("data: %w", err)
	}
	if _, err := w.Write(formatMail(cfg, m)); err != nil {
		return fmt.Errorf("write message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("finish message: %w", err)
	}
	return c.Quit()
}

func plaintextAllowed(cfg config.SMTP) bool {
	if cfg.AllowPlaintext || cfg.Host == "localhost" {
		return true
	}
	ip := net.ParseIP(cfg.Host)
	return ip != nil && ip.IsLoopback()
}

func formatMail(cfg config.SMTP, m Message) []byte {
	clean := strings.NewReplacer("\r", " ", "\n", " ")
	var b bytes.Buffer
	fmt.Fprintf(&b, "From: %s\r\n", clean.Replace(cfg.From))
	fmt.Fprintf(&b, "To: %s\r\n", clean.Replace(strings.Join(cfg.To, ", ")))
	fmt.Fprintf(&b, "Subject: %s\r\n", clean.Replace(m.Subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString(strings.ReplaceAll(m.Text, "\n", "\r\n"))
	return b.Bytes()
}
