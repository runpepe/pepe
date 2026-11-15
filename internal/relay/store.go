package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Store struct {
	*sql.DB
	path      string
	namespace string
	postgres  bool
	owner     bool
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	d, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	d.SetMaxOpenConns(1)
	_, err = d.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;

 CREATE TABLE IF NOT EXISTS activity_details (id TEXT PRIMARY KEY, payload TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS activity (id TEXT PRIMARY KEY, session TEXT NOT NULL, kind TEXT NOT NULL, result TEXT NOT NULL, destination TEXT NOT NULL, created INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS activity_session ON activity(session,created);
 CREATE TABLE IF NOT EXISTS namespaces (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, webhook_secret TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, callback TEXT NOT NULL DEFAULT '');
 CREATE TABLE IF NOT EXISTS routes (repo INTEGER NOT NULL, pr INTEGER NOT NULL, session TEXT NOT NULL, PRIMARY KEY(repo,pr));
 CREATE TABLE IF NOT EXISTS events (delivery TEXT PRIMARY KEY, session TEXT, body BLOB NOT NULL, event TEXT NOT NULL, signature TEXT NOT NULL, ack INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL DEFAULT (unixepoch()), attempt INTEGER NOT NULL DEFAULT 1);
 CREATE INDEX IF NOT EXISTS events_pending ON events(session,ack);
 CREATE TABLE IF NOT EXISTS oauth (state_hash TEXT PRIMARY KEY, session TEXT NOT NULL, provider TEXT NOT NULL, original_state TEXT NOT NULL, callback TEXT NOT NULL, expires INTEGER NOT NULL);
 `)
	if err != nil {
		d.Close()
		return nil, err
	}
	return &Store{DB: d, path: path, namespace: "default", owner: true}, nil
}
func Token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func Hash(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func (s *Store) Backup(path string) error {
	if s.postgres {
		return fmt.Errorf("use PostgreSQL backup tooling for the relay database")
	}
	_, err := s.Exec("VACUUM INTO '" + strings.ReplaceAll(path, "'", "''") + "'")
	return err
}

// OpenPostgres uses the schema managed by make migrate. Startup never applies DDL.
func OpenPostgres(connection string) (*Store, error) {
	d, err := sql.Open("pgx", connection)
	if err != nil {
		return nil, err
	}
	if err = d.Ping(); err != nil {
		d.Close()
		return nil, fmt.Errorf("connect to relay Postgres: %w", err)
	}
	return &Store{DB: d, postgres: true, namespace: "default", owner: true}, nil
}

var tableNames = regexp.MustCompile(`\b(namespaces|sessions|routes|events|oauth|activity_details|activity)\b`)

func (s *Store) query(query string) string {
	if !s.postgres {
		return query
	}
	query = tableNames.ReplaceAllString(query, "pepe_$1")
	query = strings.ReplaceAll(query, "INSERT OR IGNORE INTO", "INSERT INTO")
	if strings.Contains(query, "INSERT INTO pepe_events") {
		query += " ON CONFLICT(namespace,delivery) DO NOTHING"
	}
	query = strings.ReplaceAll(query, "ORDER BY rowid", "ORDER BY created,delivery")
	if strings.HasPrefix(query, "SELECT pepe_oauth.original_state") {
		query += " FOR UPDATE OF pepe_oauth"
	}
	if strings.HasPrefix(query, "SELECT session,body FROM pepe_events") {
		query += " FOR UPDATE"
	}

	var out strings.Builder
	index := 0
	for _, c := range query {
		if c == '?' {
			index++
			fmt.Fprintf(&out, "$%d", index)
		} else {
			out.WriteRune(c)
		}
	}
	return out.String()
}
func (s *Store) Exec(query string, args ...any) (sql.Result, error) {
	query, args = s.prepare(query, args)
	return s.DB.Exec(query, args...)
}
func (s *Store) Query(query string, args ...any) (*sql.Rows, error) {
	query, args = s.prepare(query, args)
	return s.DB.Query(query, args...)
}
func (s *Store) QueryRow(query string, args ...any) *sql.Row {
	query, args = s.prepare(query, args)
	return s.DB.QueryRow(query, args...)
}
func (s *Store) Begin() (*transaction, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	return &transaction{Tx: tx, store: s}, nil
}
func (s *Store) Close() error {
	if !s.owner {
		return nil
	}
	return s.DB.Close()
}

type transaction struct {
	*sql.Tx
	store *Store
}

func (t *transaction) Exec(query string, args ...any) (sql.Result, error) {
	query, args = t.store.prepare(query, args)
	return t.Tx.Exec(query, args...)
}
func (t *transaction) QueryRow(query string, args ...any) *sql.Row {
	query, args = t.store.prepare(query, args)
	return t.Tx.QueryRow(query, args...)
}

// SQLite namespaces use separate files and retain their original table layout.
func (s *Store) prepare(query string, args []any) (string, []any) {
	if s.postgres {
		return s.query(query), args
	}
	query = strings.ReplaceAll(query, " AND sessions.namespace=oauth.namespace", "")
	for {
		location := strings.Index(query, "namespace=? AND ")
		prefix := "namespace=? AND "
		if location < 0 {
			location = strings.Index(query, "WHERE namespace=?")
			if location < 0 {
				break
			}
			index := strings.Count(query[:location], "?")
			args = append(append([]any{}, args[:index]...), args[index+1:]...)
			query = query[:location] + strings.TrimPrefix(query[location:], "WHERE namespace=?")
			continue
		}
		if location >= 6 && query[location-6:location] == "oauth." {
			location -= 6
			prefix = "oauth." + prefix
		}
		index := strings.Count(query[:location], "?")
		args = append(append([]any{}, args[:index]...), args[index+1:]...)
		query = query[:location] + strings.TrimPrefix(query[location:], prefix)
	}
	scopedInsert := strings.Contains(query, "(namespace,") && strings.HasPrefix(query, "INSERT")
	query = strings.ReplaceAll(query, "(namespace,", "(")
	if scopedInsert {
		query = strings.Replace(query, "VALUES(?,", "VALUES(", 1)
		args = args[1:]
	}
	return query, args
}
