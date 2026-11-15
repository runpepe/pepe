package relay

import (
	"crypto/hmac"
	"database/sql"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
)

// Named namespaces have independent stores. Unprefixed requests use the original
// store so self-hosters need no namespace configuration.
func (s *Server) namespaceRequest(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/namespaces" {
		if r.Method != http.MethodPost {
			fail(w, 405, "POST required")
			return true
		}
		if !auth(r, s.AdminToken) {
			fail(w, 401, "unauthorized")
			return true
		}
		var data struct {
			ID            string `json:"id"`
			Token         string `json:"token"`
			WebhookSecret string `json:"webhook_secret"`
		}
		if !decode(w, r, &data) {
			return true
		}
		if !idPattern.MatchString(data.ID) || data.ID == "default" || len(data.Token) < 32 || len(data.WebhookSecret) < 32 {
			fail(w, 400, "named namespace ID, token and webhook secret of at least 32 characters required")
			return true
		}
		// Retrying creation with the same credentials is safe; replacing credentials
		// requires an explicit rotation instead of silently taking over a namespace.
		result, err := s.Store.Exec(`INSERT INTO namespaces(id,token_hash,webhook_secret) VALUES(?,?,?)
   ON CONFLICT(id) DO UPDATE SET id=excluded.id
   WHERE namespaces.token_hash=excluded.token_hash AND namespaces.webhook_secret=excluded.webhook_secret`, data.ID, Hash(data.Token), data.WebhookSecret)
		if err != nil {
			fail(w, 500, "database error")
			return true
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			fail(w, 409, "namespace already exists with different credentials")
			return true
		}
		reply(w, 201, map[string]string{"id": data.ID, "url": s.PublicURL + "/namespaces/" + data.ID})
		return true
	}
	if !strings.HasPrefix(r.URL.Path, "/namespaces/") {
		return false
	}
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/namespaces/"), "/", 2)
	if len(parts) != 2 || !idPattern.MatchString(parts[0]) {
		fail(w, 404, "not found")
		return true
	}
	if parts[1] == "namespaces" || strings.HasPrefix(parts[1], "namespaces/") {
		fail(w, 404, "not found")
		return true
	}
	if parts[0] == "default" {
		request := r.Clone(r.Context())
		request.URL.Path = "/" + parts[1]
		s.ServeHTTP(w, request)
		return true
	}
	var tokenHash, secret string
	err := s.Store.QueryRow("SELECT token_hash,webhook_secret FROM namespaces WHERE id=?", parts[0]).Scan(&tokenHash, &secret)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "namespace not found")
		return true
	}
	if err != nil {
		fail(w, 500, "database error")
		return true
	}
	store := &Store{DB: s.Store.DB, path: s.Store.path, postgres: s.Store.postgres, namespace: parts[0]}
	if !s.Store.postgres {
		store, err = Open(filepath.Join(s.Store.path+".namespaces", parts[0]+".sqlite"))
	}
	if err != nil {
		fail(w, 500, "namespace unavailable")
		return true
	}
	defer store.Close()
	// A namespace credential only authorizes management inside its own store.
	admin := ""
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if auth(r, s.AdminToken) || hmac.Equal([]byte(Hash(bearer)), []byte(tokenHash)) {
		admin = bearer
	}
	child := &Server{Store: store, AdminToken: admin, WebhookSecret: secret, PublicURL: s.PublicURL + "/namespaces/" + parts[0], Now: s.Now}
	request := r.Clone(r.Context())
	request.URL.Path = "/" + parts[1]
	child.ServeHTTP(w, request)
	return true
}
