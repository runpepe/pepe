package cli

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/marccampbell/pepe/internal/relay"
	"io"
	"net/http"
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
