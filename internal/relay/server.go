package relay

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{2,63}$`)
var branchPattern = regexp.MustCompile(`^pepe/([a-zA-Z0-9][a-zA-Z0-9_-]{2,63})/.+$`)

type Server struct {
	Store                                *Store
	AdminToken, WebhookSecret, PublicURL string
	Now                                  func() time.Time
}
type Event struct {
	Delivery  string `json:"delivery"`
	Body      []byte `json:"-"`
	Attempt   int64  `json:"attempt"`
	Event     string `json:"event"`
	Signature string `json:"signature"`
}

func New(s *Store, admin, secret, public string) (*Server, error) {
	if len(admin) < 32 || len(secret) < 32 {
		return nil, errors.New("admin token and webhook secret must each be at least 32 characters")
	}
	if err := ValidateURL(public); err != nil {
		return nil, fmt.Errorf("public URL: %w", err)
	}
	parsed, _ := url.Parse(public)
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("public URL must be an origin without a path")
	}
	return &Server{s, admin, secret, strings.TrimRight(public, "/"), time.Now}, nil
}
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("expected an absolute URL without credentials, query or fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")) {
		return errors.New("HTTPS is required except on loopback")
	}
	return nil
}
func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	reply(w, status, map[string]string{"error": msg})
}
func auth(r *http.Request, token string) bool {
	return token != "" && hmac.Equal([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token))
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 5_000_000)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		fail(w, 400, "invalid JSON body")
		return false
	}
	if d.Decode(new(any)) != io.EOF {
		fail(w, 400, "expected one JSON value")
		return false
	}
	return true
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method == "GET" && r.URL.Path == "/healthz" {
		if s.Store.Ping() != nil {
			fail(w, 503, "database unavailable")
		} else {
			reply(w, 200, map[string]string{"status": "ok"})
		}
		return
	}
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/oauth/") && strings.HasSuffix(r.URL.Path, "/callback") {
		s.callback(w, r)
		return
	}
	if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/sessions/") {
		s.rawEvent(w, r)
		return
	}
	if r.Method != "POST" {
		fail(w, 404, "not found")
		return
	}
	if r.URL.Path == "/github" {
		s.webhook(w, r)
		return
	}
	if r.URL.Path == "/sessions" {
		s.register(w, r)
		return
	}
	if r.URL.Path == "/status" {
		if !auth(r, s.AdminToken) {
			fail(w, 401, "unauthorized")
			return
		}
		var sessions, pending, unclaimed int
		if err := s.Store.QueryRow("SELECT (SELECT count(*) FROM sessions),(SELECT count(*) FROM events WHERE ack=0 AND session IS NOT NULL),(SELECT count(*) FROM events WHERE session IS NULL)").Scan(&sessions, &pending, &unclaimed); err != nil {
			fail(w, 500, "database error")
			return
		}
		reply(w, 200, map[string]int{"sessions": sessions, "pending": pending, "unclaimed": unclaimed})
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "sessions" || !idPattern.MatchString(parts[1]) {
		fail(w, 404, "not found")
		return
	}
	id, action := parts[1], parts[2]
	if action == "remove" {
		if !auth(r, s.AdminToken) {
			fail(w, 401, "unauthorized")
			return
		}
		if _, err := s.Store.Exec("DELETE FROM sessions WHERE id=?", id); err != nil {
			fail(w, 500, "database error")
			return
		}
		reply(w, 200, map[string]string{"removed": id})
		return
	}
	var hash string
	err := s.Store.QueryRow("SELECT token_hash FROM sessions WHERE id=?", id).Scan(&hash)
	if err != nil || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || !hmac.Equal([]byte(hash), []byte(Hash(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))) {
		fail(w, 401, "unauthorized")
		return
	}
	switch action {
	case "poll":
		s.poll(w, id)
	case "ack":
		var data struct {
			Delivery string `json:"delivery"`
			Attempt  int64  `json:"attempt"`
		}
		if !decode(w, r, &data) {
			return
		}
		if data.Attempt < 1 {
			fail(w, 400, "positive attempt required")
			return
		}
		result, err := s.Store.Exec("UPDATE events SET ack=1 WHERE session=? AND delivery=? AND attempt=?", id, data.Delivery, data.Attempt)
		if err != nil {
			fail(w, 500, "database error")
			return
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			fail(w, 409, "delivery attempt no longer current")
			return
		}
		reply(w, 200, map[string]bool{"ok": true})
	case "replay":
		s.replay(w, r, id)
	case "claim":
		s.claim(w, r, id)
	case "oauth":
		s.beginOAuth(w, r, id)
	default:
		fail(w, 404, "not found")
	}
}
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !auth(r, s.AdminToken) {
		fail(w, 401, "unauthorized")
		return
	}
	var data struct {
		ID       string `json:"id"`
		Token    string `json:"token"`
		Callback string `json:"callback"`
	}
	if !decode(w, r, &data) {
		return
	}
	if !idPattern.MatchString(data.ID) || len(data.Token) < 32 {
		fail(w, 400, "invalid session ID or token")
		return
	}
	if data.Callback != "" {
		if err := ValidateURL(data.Callback); err != nil {
			fail(w, 400, err.Error())
			return
		}
	}
	result, err := s.Store.Exec("INSERT INTO sessions(id,token_hash,callback) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET callback=excluded.callback WHERE token_hash=excluded.token_hash", data.ID, Hash(data.Token), data.Callback)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		fail(w, 409, "session belongs to another token")
		return
	}
	reply(w, 201, map[string]string{"id": data.ID})
}

type githubPayload struct {
	Repository struct {
		ID int64 `json:"id"`
	} `json:"repository"`
	Number      int64 `json:"number"`
	PullRequest *struct {
		Number int64 `json:"number"`
		Head   struct {
			Ref  string `json:"ref"`
			Repo struct {
				ID int64 `json:"id"`
			} `json:"repo"`
		} `json:"head"`
	} `json:"pull_request"`
	Issue *struct {
		Number      int64           `json:"number"`
		PullRequest json.RawMessage `json:"pull_request"`
	} `json:"issue"`
}

func route(tx *sql.Tx, p githubPayload) (string, error) {
	repo := p.Repository.ID
	var pr int64
	if p.PullRequest != nil {
		pr = p.PullRequest.Number
		if pr == 0 {
			pr = p.Number
		}
	} else if p.Issue != nil && len(p.Issue.PullRequest) > 0 && string(p.Issue.PullRequest) != "null" {
		pr = p.Issue.Number
	}
	if repo <= 0 || pr <= 0 {
		return "", nil
	}
	var id string
	err := tx.QueryRow("SELECT session FROM routes WHERE repo=? AND pr=?", repo, pr).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if p.PullRequest == nil || p.PullRequest.Head.Repo.ID != repo {
		return "", nil
	}
	matches := branchPattern.FindStringSubmatch(p.PullRequest.Head.Ref)
	if len(matches) != 2 {
		return "", nil
	}
	id = matches[1]
	var exists int
	if err = tx.QueryRow("SELECT 1 FROM sessions WHERE id=?", id).Scan(&exists); errors.Is(err, sql.ErrNoRows) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	_, err = tx.Exec("INSERT INTO routes(repo,pr,session) VALUES(?,?,?)", repo, pr, id)
	return id, err
}
func (s *Server) webhook(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 5_000_000))
	if err != nil {
		fail(w, 413, "body too large")
		return
	}
	mac := hmac.New(sha256.New, []byte(s.WebhookSecret))
	mac.Write(raw)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(r.Header.Get("X-Hub-Signature-256"))) {
		fail(w, 401, "invalid signature")
		return
	}
	event := r.Header.Get("X-GitHub-Event")
	switch event {
	case "pull_request", "pull_request_review", "pull_request_review_comment", "issue_comment":
	default:
		reply(w, 202, map[string]string{"ignored": "unsupported event"})
		return
	}
	delivery := r.Header.Get("X-GitHub-Delivery")
	if delivery == "" || len(delivery) > 200 {
		fail(w, 400, "missing or invalid delivery ID")
		return
	}
	var payload githubPayload
	if json.Unmarshal(raw, &payload) != nil {
		fail(w, 400, "invalid JSON")
		return
	}
	tx, err := s.Store.Begin()
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	id, err := route(tx, payload)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	var destination any
	if id != "" {
		destination = id
	}
	_, err = tx.Exec("INSERT OR IGNORE INTO events(delivery,session,body,event,signature) VALUES(?,?,?,?,?)", delivery, destination, raw, event, sig)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	if err = tx.Commit(); err != nil {
		fail(w, 500, "database error")
		return
	}
	reply(w, 202, map[string]bool{"queued": id != "", "unclaimed": id == ""})
}
func (s *Server) poll(w http.ResponseWriter, id string) {
	rows, err := s.Store.Query("SELECT delivery,event,signature,attempt FROM events WHERE session=? AND ack=0 ORDER BY rowid LIMIT 10", id)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer rows.Close()
	events := []Event{}
	for rows.Next() {
		var e Event
		if err = rows.Scan(&e.Delivery, &e.Event, &e.Signature, &e.Attempt); err != nil {
			fail(w, 500, "database error")
			return
		}
		events = append(events, e)
	}
	if rows.Err() != nil {
		fail(w, 500, "database error")
		return
	}
	reply(w, 200, map[string]any{"events": events})
}
func (s *Server) claim(w http.ResponseWriter, r *http.Request, id string) {
	var data struct {
		Repo int64 `json:"repo"`
		PR   int64 `json:"pr"`
	}
	if !decode(w, r, &data) {
		return
	}
	if data.Repo <= 0 || data.PR <= 0 {
		fail(w, 400, "positive repo ID and PR number required")
		return
	}
	result, err := s.Store.Exec("INSERT INTO routes(repo,pr,session) VALUES(?,?,?) ON CONFLICT(repo,pr) DO UPDATE SET session=excluded.session WHERE session=excluded.session", data.Repo, data.PR, id)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		fail(w, 409, "PR already belongs to another environment")
		return
	}
	reply(w, 200, map[string]bool{"ok": true})
}
func (s *Server) beginOAuth(w http.ResponseWriter, r *http.Request, id string) {
	var data struct {
		Provider string `json:"provider"`
		State    string `json:"state"`
	}
	if !decode(w, r, &data) {
		return
	}
	if data.Provider != "google" || len(data.State) == 0 || len(data.State) > 4096 {
		fail(w, 400, "google provider and original state required")
		return
	}
	var callback string
	if err := s.Store.QueryRow("SELECT callback FROM sessions WHERE id=?", id).Scan(&callback); err != nil || callback == "" {
		fail(w, 400, "register an exact callback URL first")
		return
	}
	token := Token()
	tx, err := s.Store.Begin()
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM oauth WHERE expires<=?", s.Now().Unix()); err == nil {
		_, err = tx.Exec("INSERT INTO oauth VALUES(?,?,?,?,?,?)", Hash(token), id, data.Provider, data.State, callback, s.Now().Add(10*time.Minute).Unix())
	}
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	if tx.Commit() != nil {
		fail(w, 500, "database error")
		return
	}
	reply(w, 201, map[string]string{"state": token, "redirect_uri": s.PublicURL + "/oauth/google/callback"})
}
func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/oauth/google/callback" {
		fail(w, 404, "not found")
		return
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		fail(w, 400, "invalid query")
		return
	}
	for _, v := range q {
		if len(v) != 1 {
			fail(w, 400, "duplicate parameter")
			return
		}
	}
	if q.Get("state") == "" || (q.Get("code") == "" && q.Get("error") == "") {
		fail(w, 400, "missing OAuth result")
		return
	}
	tx, err := s.Store.Begin()
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	var state, callback string
	err = tx.QueryRow("SELECT oauth.original_state,oauth.callback FROM oauth JOIN sessions ON sessions.id=oauth.session WHERE state_hash=? AND provider='google' AND expires>?", Hash(q.Get("state")), s.Now().Unix()).Scan(&state, &callback)
	if err != nil {
		fail(w, 400, "invalid or expired login; start again")
		return
	}
	if _, err = tx.Exec("DELETE FROM oauth WHERE state_hash=?", Hash(q.Get("state"))); err != nil {
		fail(w, 500, "database error")
		return
	}
	if tx.Commit() != nil {
		fail(w, 500, "database error")
		return
	}
	target, _ := url.Parse(callback)
	out := url.Values{"state": {state}}
	for _, k := range []string{"code", "error", "error_description"} {
		if v := q.Get(k); v != "" {
			out.Set(k, v)
		}
	}
	target.RawQuery = out.Encode()
	target.Fragment = "_"
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, target.String(), 302)
}

// rawEvent returns the exact upstream bytes, never a JSON envelope.
func (s *Server) rawEvent(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 4)
	if len(parts) != 4 || parts[0] != "sessions" || parts[2] != "events" || !idPattern.MatchString(parts[1]) {
		fail(w, 404, "not found")
		return
	}
	id, delivery := parts[1], parts[3]
	var hash string
	if err := s.Store.QueryRow("SELECT token_hash FROM sessions WHERE id=?", id).Scan(&hash); err != nil || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || !hmac.Equal([]byte(hash), []byte(Hash(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))) {
		fail(w, 401, "unauthorized")
		return
	}
	var body []byte
	var event, signature string
	var attempt int64
	err := s.Store.QueryRow("SELECT body,event,signature,attempt FROM events WHERE session=? AND delivery=?", id, delivery).Scan(&body, &event, &signature, &attempt)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "not found")
		return
	}
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	if v := r.URL.Query().Get("attempt"); v != "" && v != strconv.FormatInt(attempt, 10) {
		fail(w, 409, "delivery attempt no longer current")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-GitHub-Delivery", delivery)
	w.Header().Set("X-GitHub-Event", event)
	w.Header().Set("X-Hub-Signature-256", signature)
	w.Header().Set("X-Pepe-Attempt", strconv.FormatInt(attempt, 10))
	w.WriteHeader(200)
	_, _ = w.Write(body)
}
func (s *Server) replay(w http.ResponseWriter, r *http.Request, id string) {
	var data struct {
		Delivery string `json:"delivery"`
	}
	if !decode(w, r, &data) {
		return
	}
	tx, err := s.Store.Begin()
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	defer tx.Rollback()
	var owner sql.NullString
	var body []byte
	err = tx.QueryRow("SELECT session,body FROM events WHERE delivery=?", data.Delivery).Scan(&owner, &body)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && owner.Valid && owner.String != id) {
		fail(w, 404, "not found")
		return
	}
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	if !owner.Valid {
		var p githubPayload
		if json.Unmarshal(body, &p) != nil {
			fail(w, 500, "invalid stored payload")
			return
		}
		target, e := route(tx, p)
		if e != nil {
			fail(w, 500, "database error")
			return
		}
		if target != id {
			fail(w, 409, "delivery has no route to this session; claim its PR first")
			return
		}
	}
	var attempt int64
	err = tx.QueryRow("UPDATE events SET session=?,ack=0,attempt=attempt+1 WHERE delivery=? RETURNING attempt", id, data.Delivery).Scan(&attempt)
	if err != nil {
		fail(w, 500, "database error")
		return
	}
	if tx.Commit() != nil {
		fail(w, 500, "database error")
		return
	}
	reply(w, 200, map[string]any{"delivery": data.Delivery, "attempt": attempt, "queued": true})
}
