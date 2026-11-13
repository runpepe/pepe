package relay

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"strings"
)

type Store struct{ *sql.DB }

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

 CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, callback TEXT NOT NULL DEFAULT '');
 CREATE TABLE IF NOT EXISTS routes (repo INTEGER NOT NULL, pr INTEGER NOT NULL, session TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, PRIMARY KEY(repo,pr));
 CREATE TABLE IF NOT EXISTS events (delivery TEXT PRIMARY KEY, session TEXT REFERENCES sessions(id) ON DELETE CASCADE, body BLOB NOT NULL, event TEXT NOT NULL, signature TEXT NOT NULL, ack INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL DEFAULT (unixepoch()), attempt INTEGER NOT NULL DEFAULT 1);
 CREATE INDEX IF NOT EXISTS events_pending ON events(session,ack);
 CREATE TABLE IF NOT EXISTS oauth (state_hash TEXT PRIMARY KEY, session TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE, provider TEXT NOT NULL, original_state TEXT NOT NULL, callback TEXT NOT NULL, expires INTEGER NOT NULL);
 `)
	if err != nil {
		d.Close()
		return nil, err
	}
	return &Store{d}, nil
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
	_, err := s.Exec("VACUUM INTO '" + strings.ReplaceAll(path, "'", "''") + "'")
	return err
}
