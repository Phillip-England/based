package db

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const (
	maxFailures      = 8
	loginWindow      = 24 * time.Hour
	defaultBanPeriod = 24 * time.Hour
)

type AuthStore struct {
	db *sql.DB
}

func Open(path string) (*AuthStore, error) {
	if path == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(dir, "based", "based.sqlite")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}

	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	store := &AuthStore{db: conn}
	if err := store.migrate(); err != nil {
		conn.Close()
		return nil, err
	}
	if err := store.Purge(time.Now()); err != nil {
		conn.Close()
		return nil, err
	}
	return store, nil
}

func (s *AuthStore) Close() error {
	return s.db.Close()
}

func (s *AuthStore) migrate() error {
	_, err := s.db.Exec(`
		PRAGMA journal_mode = WAL;
		CREATE TABLE IF NOT EXISTS login_attempts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL,
			success INTEGER NOT NULL,
			attempted_at DATETIME NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_at ON login_attempts(ip, attempted_at);
		CREATE TABLE IF NOT EXISTS ip_bans (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip TEXT NOT NULL UNIQUE,
			banned_until DATETIME NOT NULL,
			created_at DATETIME NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_ip_bans_until ON ip_bans(banned_until);
	`)
	return err
}

func (s *AuthStore) Purge(now time.Time) error {
	cutoff := now.Add(-loginWindow)
	_, err := s.db.Exec(`DELETE FROM login_attempts WHERE attempted_at < ?; DELETE FROM ip_bans WHERE banned_until <= ?;`, cutoff.UTC(), now.UTC())
	return err
}

func (s *AuthStore) IsBanned(ip string, now time.Time) (bool, time.Time, error) {
	if err := s.Purge(now); err != nil {
		return false, time.Time{}, err
	}
	var until time.Time
	err := s.db.QueryRow(`SELECT banned_until FROM ip_bans WHERE ip = ? AND banned_until > ?`, ip, now.UTC()).Scan(&until)
	if errors.Is(err, sql.ErrNoRows) {
		return false, time.Time{}, nil
	}
	if err != nil {
		return false, time.Time{}, err
	}
	return true, until, nil
}

func (s *AuthStore) RecordSuccess(ip string, now time.Time) error {
	if err := s.Purge(now); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT INTO login_attempts(ip, success, attempted_at) VALUES(?, 1, ?)`, ip, now.UTC())
	return err
}

func (s *AuthStore) RecordFailure(ip string, now time.Time) (bool, time.Time, error) {
	if err := s.Purge(now); err != nil {
		return false, time.Time{}, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, time.Time{}, err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`INSERT INTO login_attempts(ip, success, attempted_at) VALUES(?, 0, ?)`, ip, now.UTC()); err != nil {
		return false, time.Time{}, err
	}
	var failures int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND success = 0 AND attempted_at >= ?`, ip, now.Add(-loginWindow).UTC()).Scan(&failures); err != nil {
		return false, time.Time{}, err
	}
	var until time.Time
	if failures >= maxFailures {
		until = now.Add(defaultBanPeriod).UTC()
		if _, err := tx.Exec(`
			INSERT INTO ip_bans(ip, banned_until, created_at) VALUES(?, ?, ?)
			ON CONFLICT(ip) DO UPDATE SET banned_until = excluded.banned_until, created_at = excluded.created_at
		`, ip, until, now.UTC()); err != nil {
			return false, time.Time{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, time.Time{}, err
	}
	return failures >= maxFailures, until, nil
}
