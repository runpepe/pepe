package relay

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNamespaceIsolation(t *testing.T) {
	f := setup(t)
	for _, name := range []string{"alpha", "bravo"} {
		token := strings.Repeat(name, 8)
		secret := strings.Repeat(name, 9)
		w := f.req("POST", "/namespaces", f.s.AdminToken, map[string]string{"id": name, "token": token, "webhook_secret": secret})
		if w.Code != 201 {
			t.Fatalf("create: %d %s", w.Code, w.Body)
		}
		w = f.req("POST", "/namespaces/"+name+"/sessions", token, map[string]string{"id": "p_one", "token": strings.Repeat(name, 10), "callback": "https://" + name + ".example/callback"})
		if w.Code != 201 {
			t.Fatalf("register: %d %s", w.Code, w.Body)
		}
		w = f.req("POST", "/namespaces/"+name+"/sessions/p_one/claim", strings.Repeat(name, 10), map[string]int{"repo": 1, "pr": 42})
		if w.Code != 200 {
			t.Fatalf("claim: %d %s", w.Code, w.Body)
		}
	}
	if w := f.req("POST", "/namespaces/bravo/sessions", strings.Repeat("alpha", 8), map[string]string{"id": "p_bad", "token": strings.Repeat("z", 32)}); w.Code != 401 {
		t.Fatalf("cross namespace admin: %d", w.Code)
	}
	if w := f.req("POST", "/namespaces/bravo/sessions/p_one/poll", strings.Repeat("alpha", 10), struct{}{}); w.Code != 401 {
		t.Fatalf("cross namespace session: %d", w.Code)
	}
	if w := f.req("POST", "/namespaces/bravo/namespaces", strings.Repeat("bravo", 8), struct{}{}); w.Code != 404 {
		t.Fatalf("nested namespace: %d", w.Code)
	}
	w := f.req("POST", "/namespaces/alpha/sessions/p_one/oauth", strings.Repeat("alpha", 10), map[string]string{"provider": "google", "state": "original"})
	if w.Code != 201 {
		t.Fatalf("oauth: %d %s", w.Code, w.Body)
	}
	var transaction map[string]string
	json.Unmarshal(w.Body.Bytes(), &transaction)
	if transaction["redirect_uri"] != "https://relay.example/namespaces/alpha/oauth/google/callback" {
		t.Fatal(transaction)
	}
	if w = f.req("GET", "/namespaces/bravo/oauth/google/callback?state="+transaction["state"]+"&code=code", "", nil); w.Code != 400 {
		t.Fatalf("cross namespace oauth: %d", w.Code)
	}
	w = f.req("GET", "/namespaces/alpha/oauth/google/callback?state="+transaction["state"]+"&code=code", "", nil)
	if w.Code != 302 || !strings.HasPrefix(w.Header().Get("Location"), "https://alpha.example/callback?") {
		t.Fatalf("callback: %d %s", w.Code, w.Header())
	}
	if w = f.req("POST", "/namespaces/default/sessions/p_one/poll", strings.Repeat("t", 32), struct{}{}); w.Code != 200 {
		t.Fatalf("default: %d", w.Code)
	}
}

func TestNamespaceCreationAuthorization(t *testing.T) {
	f := setup(t)
	data := map[string]string{"id": "alpha", "token": strings.Repeat("t", 32), "webhook_secret": strings.Repeat("s", 32)}
	if w := f.req("POST", "/namespaces", "wrong", data); w.Code != 401 {
		t.Fatal(w.Code)
	}
	for _, code := range []int{201, 201} {
		if w := f.req("POST", "/namespaces", f.s.AdminToken, data); w.Code != code {
			t.Fatal(w.Code)
		}
	}
	data["token"] = strings.Repeat("x", 32)
	if w := f.req("POST", "/namespaces", f.s.AdminToken, data); w.Code != 409 {
		t.Fatal(w.Code)
	}
	for _, id := range []string{"default", "../escape", "bad/name"} {
		data["id"] = id
		if w := f.req("POST", "/namespaces", f.s.AdminToken, data); w.Code != 400 {
			t.Fatal(id, w.Code)
		}
	}
	// Selecting a namespace in a header has no effect on the default store.
	r := httptest.NewRequest("POST", "/sessions/p_one/poll", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("t", 32))
	r.Header.Set("X-Pepe-Namespace", "alpha")
	w := httptest.NewRecorder()
	f.s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func TestNamespaceDeliveries(t *testing.T) {
	f := setup(t)
	for _, name := range []string{"alpha", "bravo"} {
		management := strings.Repeat(name, 8)
		f.req("POST", "/namespaces", f.s.AdminToken, map[string]string{"id": name, "token": management, "webhook_secret": management})
		f.req("POST", "/namespaces/"+name+"/sessions", management, map[string]string{"id": "p_one", "token": strings.Repeat(name, 10)})
		r := httptest.NewRequest("POST", "/namespaces/"+name+"/github", strings.NewReader(pr("pepe/p_one/test", false)))
		mac := hmac.New(sha256.New, []byte(management))
		mac.Write([]byte(pr("pepe/p_one/test", false)))
		r.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		r.Header.Set("X-GitHub-Event", "pull_request")
		r.Header.Set("X-GitHub-Delivery", "same-delivery")
		w := httptest.NewRecorder()
		f.s.ServeHTTP(w, r)
		if w.Code != 202 {
			t.Fatalf("webhook: %d %s", w.Code, w.Body)
		}
		w = f.req("POST", "/namespaces/"+name+"/sessions/p_one/poll", strings.Repeat(name, 10), struct{}{})
		var batch struct {
			Events []Event `json:"events"`
		}
		json.Unmarshal(w.Body.Bytes(), &batch)
		if w.Code != 200 || len(batch.Events) != 1 {
			t.Fatalf("poll: %d %s", w.Code, w.Body)
		}
	}
	if got := f.poll("p_one", "t"); len(got) != 0 {
		t.Fatal("namespace deliveries leaked into default")
	}
}
