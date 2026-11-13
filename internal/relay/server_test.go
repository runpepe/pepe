package relay

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	s    *Server
	path string
	t    *testing.T
}

func setup(t *testing.T) *fixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.sqlite")
	db, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { db.Close() })
	s, e := New(db, strings.Repeat("a", 32), strings.Repeat("s", 32), "https://relay.example")
	if e != nil {
		t.Fatal(e)
	}
	f := &fixture{s, path, t}
	f.register("p_one", "t")
	return f
}
func (f *fixture) req(method, path, token string, v any) *httptest.ResponseRecorder {
	f.t.Helper()
	b, _ := json.Marshal(v)
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.s.ServeHTTP(w, r)
	return w
}
func (f *fixture) register(id, token string) {
	f.t.Helper()
	w := f.req("POST", "/sessions", f.s.AdminToken, map[string]string{"id": id, "token": strings.Repeat(token, 32), "callback": "https://workspace.example/auth/callback/google"})
	if w.Code != 201 {
		f.t.Fatalf("register: %d %s", w.Code, w.Body)
	}
}
func (f *fixture) webhook(body, event, delivery string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/github", strings.NewReader(body))
	m := hmac.New(sha256.New, []byte(f.s.WebhookSecret))
	m.Write([]byte(body))
	r.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(m.Sum(nil)))
	r.Header.Set("X-GitHub-Event", event)
	r.Header.Set("X-GitHub-Delivery", delivery)
	w := httptest.NewRecorder()
	f.s.ServeHTTP(w, r)
	return w
}
func pr(branch string, fork bool) string {
	repo := 1
	if fork {
		repo = 2
	}
	return fmt.Sprintf(`{ "repository": {"id":1}, "pull_request":{"number":42,"head":{"ref":%q,"repo":{"id":%d}}}}`, branch, repo)
}
func (f *fixture) poll(id, token string) []Event {
	f.t.Helper()
	w := f.req("POST", "/sessions/"+id+"/poll", strings.Repeat(token, 32), struct{}{})
	if w.Code != 200 {
		f.t.Fatalf("poll: %d %s", w.Code, w.Body)
	}
	var out struct {
		Events []Event `json:"events"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil {
		f.t.Fatal(e)
	}
	for i := range out.Events {
		e := &out.Events[i]
		raw := f.req("GET", "/sessions/"+id+"/events/"+e.Delivery+"?attempt=1", strings.Repeat(token, 32), nil)
		if raw.Code != 200 {
			f.t.Fatalf("raw payload: %d", raw.Code)
		}
		e.Body = raw.Body.Bytes()
	}
	return out.Events
}
func TestRouteDedupeAckAndOriginalBytes(t *testing.T) {
	f := setup(t)
	body := pr("pepe/p_one/fix", false)
	for range 2 {
		if w := f.webhook(body, "pull_request", "one"); w.Code != 202 {
			t.Fatal(w.Code, w.Body)
		}
	}
	es := f.poll("p_one", "t")
	if len(es) != 1 || string(es[0].Body) != body {
		t.Fatalf("payload changed: %+v", es)
	}
	f.req("POST", "/sessions/p_one/ack", strings.Repeat("t", 32), map[string]any{"delivery": "one", "attempt": 1})
	if len(f.poll("p_one", "t")) != 0 {
		t.Fatal("ack failed")
	}
}
func TestPinnedCommentsAndRename(t *testing.T) {
	f := setup(t)
	f.webhook(pr("pepe/p_one/fix", false), "pull_request_review", "review")
	f.webhook(pr("renamed", false), "pull_request", "rename")
	f.webhook(`{"repository":{"id":1},"issue":{"number":42,"pull_request":{}}}`, "issue_comment", "comment")
	f.webhook(`{"repository":{"id":1},"issue":{"number":42}}`, "issue_comment", "issue")
	if len(f.poll("p_one", "t")) != 3 {
		t.Fatal("pin routing failed")
	}
}
func TestUnknownForkAndAuthentication(t *testing.T) {
	f := setup(t)
	f.webhook(pr("pepe/p_one/fix", true), "pull_request", "fork")
	f.webhook(pr("pepe/p_missing/fix", false), "pull_request", "unknown")
	if len(f.poll("p_one", "t")) != 0 {
		t.Fatal("unclaimed routed")
	}
	if w := f.req("POST", "/sessions/p_one/poll", "wrong", struct{}{}); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := f.req("POST", "/github", "", struct{}{})
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	r := httptest.NewRequest("POST", "/sessions/p_one/poll", strings.NewReader("{}"))
	r.Header.Set("Authorization", strings.Repeat("t", 32))
	out := httptest.NewRecorder()
	f.s.ServeHTTP(out, r)
	if out.Code != 401 {
		t.Fatal("missing Bearer accepted")
	}
}
func TestIsolationRemovalAndClaim(t *testing.T) {
	f := setup(t)
	f.register("p_two", "x")
	f.webhook(pr("pepe/p_one/fix", false), "pull_request", "one")
	f.req("POST", "/sessions/p_two/ack", strings.Repeat("x", 32), map[string]any{"delivery": "one", "attempt": 1})
	if len(f.poll("p_one", "t")) != 1 {
		t.Fatal("cross-session ack")
	}
	w := f.req("POST", "/sessions/p_two/claim", strings.Repeat("x", 32), map[string]int{"repo": 1, "pr": 42})
	if w.Code != 409 {
		t.Fatal("claim stole route")
	}
	f.req("POST", "/sessions/p_one/remove", f.s.AdminToken, struct{}{})
	if w = f.req("POST", "/sessions/p_one/poll", strings.Repeat("t", 32), struct{}{}); w.Code != 401 {
		t.Fatal("deleted session active")
	}
	var n int
	f.s.Store.QueryRow("SELECT count(*) FROM routes").Scan(&n)
	if n != 0 {
		t.Fatal("routes remain")
	}
}
func TestPersistence(t *testing.T) {
	f := setup(t)
	f.webhook(pr("pepe/p_one/fix", false), "pull_request", "one")
	f.s.Store.Close()
	db, e := Open(f.path)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	f.s.Store = db
	if len(f.poll("p_one", "t")) != 1 {
		t.Fatal("queue lost")
	}
	f.webhook(pr("renamed", false), "pull_request", "two")
	if len(f.poll("p_one", "t")) != 2 {
		t.Fatal("route lost")
	}
}
func TestOAuthRoundTripReplayExpiryAndDuplicates(t *testing.T) {
	f := setup(t)
	start := func() string {
		t.Helper()
		w := f.req("POST", "/sessions/p_one/oauth", strings.Repeat("t", 32), map[string]string{"provider": "google", "state": "app-cookie-state"})
		if w.Code != 201 {
			t.Fatal(w.Code, w.Body)
		}
		var v map[string]string
		json.Unmarshal(w.Body.Bytes(), &v)
		if v["redirect_uri"] != "https://relay.example/oauth/google/callback" {
			t.Fatal(v)
		}
		return v["state"]
	}
	state := start()
	path := "/oauth/google/callback?state=" + state + "&code=code"
	w := f.req("GET", path, "", nil)
	if w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "state=app-cookie-state") {
		t.Fatal(w.Code, w.Header())
	}
	if f.req("GET", path, "", nil).Code != 400 {
		t.Fatal("replay accepted")
	}
	state = start()
	if f.req("GET", "/oauth/google/callback?state="+state+"&state=x&code=c", "", nil).Code != 400 {
		t.Fatal("duplicate accepted")
	}
	f.s.Now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if f.req("GET", "/oauth/google/callback?state="+state+"&code=c", "", nil).Code != 400 {
		t.Fatal("expired accepted")
	}
}
func TestValidationAndBackup(t *testing.T) {
	f := setup(t)
	w := f.req("POST", "/sessions", f.s.AdminToken, map[string]string{"id": "p_bad", "token": strings.Repeat("q", 32), "callback": "https://evil.example/?next=x"})
	if w.Code != 400 {
		t.Fatal("query callback accepted")
	}
	if w = f.req("POST", "/sessions", f.s.AdminToken, map[string]string{"id": "p_one", "token": strings.Repeat("x", 32)}); w.Code != 409 {
		t.Fatal("session overwritten")
	}
	backup := filepath.Join(t.TempDir(), "backup.sqlite")
	if e := f.s.Store.Backup(backup); e != nil {
		t.Fatal(e)
	}
	db, e := Open(backup)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var count int
	if e = db.QueryRow("SELECT count(*) FROM sessions").Scan(&count); e != nil || count != 1 {
		t.Fatal(count, e)
	}
}
func TestHealthAndUnsupportedEvent(t *testing.T) {
	f := setup(t)
	if f.req("GET", "/healthz", "", nil).Code != http.StatusOK {
		t.Fatal("unhealthy")
	}
	f.webhook(pr("pepe/p_one/fix", false), "push", "push")
	if len(f.poll("p_one", "t")) != 0 {
		t.Fatal("unsupported event routed")
	}
}

func TestOAuthDestinationIsBoundAtCreation(t *testing.T) {
	f := setup(t)
	w := f.req("POST", "/sessions/p_one/oauth", strings.Repeat("t", 32), map[string]string{"provider": "google", "state": "original"})
	var transaction map[string]string
	if e := json.Unmarshal(w.Body.Bytes(), &transaction); e != nil {
		t.Fatal(e)
	}
	w = f.req("POST", "/sessions", f.s.AdminToken, map[string]string{"id": "p_one", "token": strings.Repeat("t", 32), "callback": "https://other.example/callback"})
	if w.Code != 201 {
		t.Fatal(w.Code)
	}
	w = f.req("GET", "/oauth/google/callback?state="+transaction["state"]+"&code=c", "", nil)
	if !strings.HasPrefix(w.Header().Get("Location"), "https://workspace.example/") {
		t.Fatal("transaction destination changed", w.Header())
	}
}

func TestRawPayloadMetadataAndLegacyRemoval(t *testing.T) {
	f := setup(t)
	body := pr("pepe/p_one/fix", false)
	f.webhook(body, "pull_request", "raw")
	w := f.req("POST", "/sessions/p_one/poll", strings.Repeat("t", 32), struct{}{})
	var out map[string][]map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["events"][0]["body"]; ok {
		t.Fatal("body must not be encoded in poll response")
	}
	w = f.req("GET", "/sessions/p_one/events/raw?attempt=1", strings.Repeat("t", 32), nil)
	if w.Code != 200 || w.Body.String() != body || w.Header().Get("X-GitHub-Delivery") != "raw" || w.Header().Get("X-Pepe-Attempt") != "1" {
		t.Fatal("raw response changed payload", w.Code, w.Header())
	}
	if f.req("GET", "/sessions/p_one/events/raw", strings.Repeat("x", 32), nil).Code != 401 {
		t.Fatal("raw access unprotected")
	}
	f.register("p_two", "x")
	if f.req("GET", "/sessions/p_two/events/raw", strings.Repeat("x", 32), nil).Code != 404 {
		t.Fatal("cross-session payload access")
	}
	f.webhook(strings.Replace(pr("dev/p_one/fix", false), `"number":42`, `"number":43`, 1), "pull_request", "legacy")
	if len(f.poll("p_one", "t")) != 1 {
		t.Fatal("legacy prefix accepted")
	}
}
func TestReplayAndStaleAcknowledgement(t *testing.T) {
	f := setup(t)
	f.webhook(pr("pepe/p_one/fix", false), "pull_request", "replay")
	tok := strings.Repeat("t", 32)
	if f.req("POST", "/sessions/p_one/ack", tok, map[string]any{"delivery": "replay", "attempt": 1}).Code != 200 {
		t.Fatal("ack failed")
	}
	w := f.req("POST", "/sessions/p_one/replay", tok, map[string]string{"delivery": "replay"})
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if f.req("POST", "/sessions/p_one/ack", tok, map[string]any{"delivery": "replay", "attempt": 1}).Code != 409 {
		t.Fatal("stale ack cleared replay")
	}
	if f.req("GET", "/sessions/p_one/events/replay?attempt=1", tok, nil).Code != 409 {
		t.Fatal("stale fetch accepted")
	}
	if f.req("GET", "/sessions/p_one/events/replay?attempt=2", tok, nil).Code != 200 {
		t.Fatal("replay not fetchable")
	}
	if f.req("POST", "/sessions/p_one/ack", tok, map[string]any{"delivery": "replay", "attempt": 2}).Code != 200 {
		t.Fatal("new ack failed")
	}
	f.register("p_two", "x")
	if f.req("POST", "/sessions/p_two/replay", strings.Repeat("x", 32), map[string]string{"delivery": "replay"}).Code != 404 {
		t.Fatal("cross-session replay accepted")
	}
}
func TestUnclaimedReplayResolvesCurrentOwner(t *testing.T) {
	f := setup(t)
	tok := strings.Repeat("t", 32)
	body := `{"repository":{"id":1},"issue":{"number":99,"pull_request":{"url":"https://example.com/pr"}}}`
	f.webhook(body, "issue_comment", "unclaimed")
	replay := func() *httptest.ResponseRecorder {
		return f.req("POST", "/sessions/p_one/replay", tok, map[string]string{"delivery": "unclaimed"})
	}
	if replay().Code != 409 {
		t.Fatal("unclaimed routed without ownership")
	}
	f.req("POST", "/sessions/p_one/claim", tok, map[string]int{"repo": 1, "pr": 99})
	if w := replay(); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w := f.req("GET", "/sessions/p_one/events/unclaimed?attempt=2", tok, nil)
	if w.Code != 200 || w.Body.String() != body {
		t.Fatal("replayed payload changed")
	}
	f.webhook(body, "issue_comment", "unclaimed")
	var attempt int
	if e := f.s.Store.QueryRow("SELECT attempt FROM events WHERE delivery='unclaimed'").Scan(&attempt); e != nil || attempt != 2 {
		t.Fatal("upstream duplicate reset replay generation")
	}
}
