package mcpmanifest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPuller_FetchesAndCaches(t *testing.T) {
	manifest := `[{"name":"read","capability":"fs.read","scope":"workspace"}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(manifest))
	}))
	defer srv.Close()

	p := NewPuller(srv.URL, 0)
	got, err := p.Pull(context.Background())
	if err != nil {
		t.Fatalf("pull: %v", err)
	}
	if string(got) != manifest || string(p.Cached()) != manifest {
		t.Fatalf("cached %q, want %q", p.Cached(), manifest)
	}
}

func TestPuller_RejectsInvalidManifest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	if _, err := NewPuller(srv.URL, 0).Pull(context.Background()); err == nil {
		t.Fatal("expected invalid manifest to be rejected")
	}
}

func TestPuller_RejectsNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := NewPuller(srv.URL, 0).Pull(context.Background()); err == nil {
		t.Fatal("expected HTTP 404 to be rejected")
	}
}
