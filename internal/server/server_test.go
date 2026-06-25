package server

import "testing"

func TestValidCredentialsRequiresMatrix(t *testing.T) {
	s := &Server{adminUsername: "admin", adminPassword: "secret"}

	if !s.validCredentials("admin", "secret", "258") {
		t.Fatal("expected credentials with matrix 258 to be valid")
	}
	if s.validCredentials("admin", "secret", "") {
		t.Fatal("expected missing matrix to be invalid")
	}
	if s.validCredentials("admin", "secret", "25") {
		t.Fatal("expected partial matrix to be invalid")
	}
	if s.validCredentials("admin", "secret", "2589") {
		t.Fatal("expected extra matrix cells to be invalid")
	}
}
