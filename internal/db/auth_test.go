package db

import (
	"path/filepath"
	"testing"
	"time"
)

func TestRecordFailureBansAndExpires(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "based.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	ip := "203.0.113.10"
	for i := 0; i < maxFailures-1; i++ {
		banned, _, err := store.RecordFailure(ip, now.Add(time.Duration(i)*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		if banned {
			t.Fatalf("failure %d unexpectedly banned ip", i+1)
		}
	}

	banned, until, err := store.RecordFailure(ip, now.Add(time.Duration(maxFailures)*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !banned {
		t.Fatal("expected ip to be banned")
	}

	isBanned, gotUntil, err := store.IsBanned(ip, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !isBanned || !gotUntil.Equal(until) {
		t.Fatalf("expected active ban until %s, got banned=%v until=%s", until, isBanned, gotUntil)
	}

	isBanned, _, err = store.IsBanned(ip, until.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if isBanned {
		t.Fatal("expected ban to be purged after expiry")
	}
}

func TestPurgeDeletesOldLoginAttempts(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "based.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	if _, _, err := store.RecordFailure("203.0.113.20", now.Add(-25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.RecordFailure("203.0.113.20", now); err != nil {
		t.Fatal(err)
	}
	if err := store.Purge(now); err != nil {
		t.Fatal(err)
	}

	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM login_attempts`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 recent attempt after purge, got %d", count)
	}
}
