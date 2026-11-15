package relay

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestOAuthActivityIsPersistentScopedAndSanitized(t *testing.T) {
	f := setup(t)
	w := f.req("POST", "/sessions/p_one/oauth", strings.Repeat("t", 32), map[string]string{"provider": "google", "state": "secret-original-state"})
	var transaction map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &transaction); err != nil {
		t.Fatal(err)
	}
	w = f.req("GET", "/oauth/google/callback?state="+transaction["state"]+"&code=secret-code&iss=https%3A%2F%2Faccounts.google.com", "", nil)
	if w.Code != 302 {
		t.Fatal(w.Code, w.Body)
	}
	w = f.req("GET", "/sessions/p_one/activity", f.s.AdminToken, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	body := w.Body.String()
	for _, secret := range []string{"secret-code", "secret-original-state", transaction["state"]} {
		if strings.Contains(body, secret) {
			t.Fatal("secret in activity")
		}
	}
	var result struct {
		Activity []Activity `json:"activity"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Activity) > 0 && len(result.Activity[0].Details) == 0 {
		t.Fatal("request details missing")
	}
	if len(result.Activity) != 2 {
		t.Fatal(body)
	}
	if f.req("GET", "/sessions/p_one/activity", strings.Repeat("t", 32), nil).Code != 401 {
		t.Fatal("session token accessed admin activity")
	}
	w = f.req("GET", "/sessions/p_other/activity", f.s.AdminToken, nil)
	json.Unmarshal(w.Body.Bytes(), &result)
	if len(result.Activity) != 0 {
		t.Fatal("other session activity leaked")
	}
}
