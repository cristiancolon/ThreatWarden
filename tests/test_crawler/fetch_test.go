package test_crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/threatwarden/crawler/pipeline"
)

// -- FetchURL ------------------------------------------------------------------

func TestFetch_Returns200Body(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>advisory content</body></html>"))
	}))
	defer srv.Close()

	result := pipeline.FetchURL(context.Background(), pipeline.CrawlJob{
		CveID: "CVE-2025-0001", URL: srv.URL, Domain: "test",
	})

	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}
	if len(result.HTMLBody) == 0 {
		t.Fatal("expected non-empty body")
	}
	if result.Job.CveID != "CVE-2025-0001" {
		t.Errorf("CveID not preserved: got %q", result.Job.CveID)
	}
}

func TestFetch_ReturnsErrorOn404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	result := pipeline.FetchURL(context.Background(), pipeline.CrawlJob{
		URL: srv.URL, Domain: "test",
	})

	if result.Err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestFetch_ReturnsErrorOn500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	result := pipeline.FetchURL(context.Background(), pipeline.CrawlJob{
		URL: srv.URL, Domain: "test",
	})

	if result.Err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestFetch_ReturnsErrorOnTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	result := pipeline.FetchURL(ctx, pipeline.CrawlJob{
		URL: srv.URL, Domain: "test",
	})

	if result.Err == nil {
		t.Fatal("expected error on timeout")
	}
}

func TestFetch_ReturnsErrorOnConnectionRefused(t *testing.T) {
	result := pipeline.FetchURL(context.Background(), pipeline.CrawlJob{
		URL: "http://127.0.0.1:1", Domain: "test",
	})

	if result.Err == nil {
		t.Fatal("expected error on connection refused")
	}
}

func TestFetch_PreservesJobFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	job := pipeline.CrawlJob{CveID: "CVE-2025-9999", URL: srv.URL, Domain: "example.com"}
	result := pipeline.FetchURL(context.Background(), job)

	if result.Job.CveID != job.CveID {
		t.Errorf("CveID: got %q, want %q", result.Job.CveID, job.CveID)
	}
	if result.Job.Domain != job.Domain {
		t.Errorf("Domain: got %q, want %q", result.Job.Domain, job.Domain)
	}
}
