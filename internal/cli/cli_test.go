package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/marccampbell/pepe/internal/relay"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkspacePersistsPrivateIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".pepe", "identity.json")
	a, e := workspace(path)
	if e != nil {
		t.Fatal(e)
	}
	b, e := workspace(path)
	if e != nil || a != b {
		t.Fatal("identity changed", e)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("identity not private")
	}
}
func TestDeliveryPreservesBytesAndSigning(t *testing.T) {
	body := []byte(`{ "a": 1 }`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, len(body))
		r.Body.Read(b)
		if string(b) != string(body) {
			t.Error("body changed")
		}
		m := hmac.New(sha256.New, []byte("local"))
		m.Write(body)
		if r.Header.Get("X-Hub-Signature-256") != "sha256="+hex.EncodeToString(m.Sum(nil)) {
			t.Error("signature invalid")
		}
		if r.Header.Get("X-GitHub-Delivery") != "d" {
			t.Error("delivery missing")
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	if e := deliver(context.Background(), apiClient(), srv.URL, "local", relay.Event{Body: body, Delivery: "d", Event: "pull_request"}); e != nil {
		t.Fatal(e)
	}
}
func TestDeliveryRejectsFailureAndRedirect(t *testing.T) {
	for _, status := range []int{302, 500} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "https://example.com")
			w.WriteHeader(status)
		}))
		if e := deliver(context.Background(), apiClient(), srv.URL, "", relay.Event{Body: []byte(`{}`)}); e == nil {
			t.Fatal("failed delivery accepted")
		}
		srv.Close()
	}
}
func TestAtomicWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "binary")
	os.WriteFile(p, []byte("old"), 0755)
	if e := atomicWrite(p, []byte("new"), 0755); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "new" {
		t.Fatal(string(b))
	}
}
func TestInstallDryRunAndValidation(t *testing.T) {
	if e := install([]string{"--domain", "pepe.example.com", "--proxy", "caddy", "--dry-run"}); e != nil {
		t.Fatal(e)
	}
	if e := install([]string{"--domain", "bad\nexample.com", "--dry-run"}); e == nil {
		t.Fatal("injection accepted")
	}
	if e := install([]string{"--public-url", "https://example.com/path", "--dry-run"}); e == nil {
		t.Fatal("path accepted")
	}
}
func TestManifestRejectsUnsignedAndTampered(t *testing.T) {
	if _, e := verifyManifest([]byte(`{"version":"v0.1.0"}`), make([]byte, ed25519.SignatureSize), "v0.1.0"); e == nil {
		t.Fatal("unsigned accepted")
	}
	if _, e := verifyManifest([]byte("bad"), []byte("bad"), "v0.1.0"); e == nil {
		t.Fatal("malformed accepted")
	}
}
func TestRequestDoesNotLeakTokenOnRedirect(t *testing.T) {
	var called bool
	dest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer dest.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, dest.URL, 307) }))
	defer src.Close()
	e := request(context.Background(), apiClient(), src.URL, "/status", strings.Repeat("a", 32), struct{}{}, nil)
	if e == nil || called {
		t.Fatal("redirect followed")
	}
}
