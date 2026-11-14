package cli

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/runpepe/pepe/internal/relay"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func deliver(ctx context.Context, client *http.Client, target, secret string, e relay.Event) error {
	req, err := http.NewRequestWithContext(ctx, "POST", target, bytes.NewReader(e.Body))
	if err != nil {
		return err
	}
	sig := e.Signature
	if secret != "" {
		m := hmac.New(sha256.New, []byte(secret))
		m.Write(e.Body)
		sig = "sha256=" + hex.EncodeToString(m.Sum(nil))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", e.Event)
	req.Header.Set("X-GitHub-Delivery", e.Delivery)
	if e.Attempt > 0 {
		req.Header.Set("X-Pepe-Attempt", strconv.FormatInt(e.Attempt, 10))
	}
	req.Header.Set("X-Hub-Signature-256", sig)
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 65536))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("local receiver returned HTTP %d", res.StatusCode)
	}
	return nil
}

func fetchEvent(ctx context.Context, client *http.Client, server string, i identity, e *relay.Event) error {
	path := strings.TrimRight(server, "/") + "/sessions/" + url.PathEscape(i.ID) + "/events/" + url.PathEscape(e.Delivery) + "?attempt=" + strconv.FormatInt(e.Attempt, 10)
	req, err := http.NewRequestWithContext(ctx, "GET", path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+i.Token)
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("payload fetch returned HTTP %d", res.StatusCode)
	}
	e.Body, err = io.ReadAll(io.LimitReader(res.Body, 5_000_001))
	if err != nil {
		return err
	}
	if len(e.Body) > 5_000_000 {
		return fmt.Errorf("payload too large")
	}
	e.Event = res.Header.Get("X-GitHub-Event")
	e.Signature = res.Header.Get("X-Hub-Signature-256")
	return nil
}
