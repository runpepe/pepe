package relay

import (
	"strings"
	"testing"
)

func TestPostgresQueries(t *testing.T) {
	store := &Store{postgres: true}
	cases := []struct{ query, want string }{
		{"SELECT token_hash FROM sessions WHERE namespace=? AND id=?", "SELECT token_hash FROM pepe_sessions WHERE namespace=$1 AND id=$2"},
		{"INSERT OR IGNORE INTO events(namespace,delivery,body) VALUES(?,?,?)", "INSERT INTO pepe_events(namespace,delivery,body) VALUES($1,$2,$3) ON CONFLICT(namespace,delivery) DO NOTHING"},
		{"SELECT delivery FROM events WHERE namespace=? ORDER BY rowid LIMIT 10", "SELECT delivery FROM pepe_events WHERE namespace=$1 ORDER BY created,delivery LIMIT 10"},
		{"INSERT INTO sessions(namespace,id,token_hash) VALUES(?,?,?) ON CONFLICT(namespace,id) DO UPDATE SET token_hash=excluded.token_hash WHERE sessions.token_hash=excluded.token_hash", "INSERT INTO pepe_sessions(namespace,id,token_hash) VALUES($1,$2,$3) ON CONFLICT(namespace,id) DO UPDATE SET token_hash=excluded.token_hash WHERE pepe_sessions.token_hash=excluded.token_hash"},
	}
	for _, c := range cases {
		if got := store.query(c.query); got != c.want {
			t.Fatalf("got %s; want %s", got, c.want)
		}
	}
	if got := store.query("SELECT session,body FROM events WHERE namespace=? AND delivery=?"); !strings.HasSuffix(got, "FOR UPDATE") {
		t.Fatal(got)
	}
	if got := store.query("SELECT oauth.original_state FROM oauth JOIN sessions ON sessions.id=oauth.session WHERE oauth.namespace=?"); !strings.HasSuffix(got, "FOR UPDATE OF pepe_oauth") {
		t.Fatal(got)
	}
}

func TestSQLiteStatusNamespaceTranslation(t *testing.T) {
	f := setup(t)
	w := f.req("POST", "/status", f.s.AdminToken, struct{}{})
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
