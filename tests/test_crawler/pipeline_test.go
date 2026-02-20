package test_crawler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/threatwarden/crawler/pipeline"
)

// -- Pipeline channel flow -----------------------------------------------------

func TestPipeline_JobFlowsThroughAllStages(t *testing.T) {
	fetchSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(sampleHTML)
	}))
	defer fetchSrv.Close()

	embedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(pipeline.EmbeddingResponse{
			Data: []pipeline.EmbeddingData{{Embedding: make([]float32, 1536)}},
		})
	}))
	defer embedSrv.Close()

	cfg := pipeline.Config{
		EmbedEndpoint: embedSrv.URL,
		OpenAIKey:     "test-key",
		EmbedModel:    "test-model",
		EmbedBatch:    1,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	jobs := make(chan pipeline.CrawlJob, 1)
	fetched := make(chan pipeline.FetchResult, 1)
	extracted := make(chan pipeline.ExtractedText, 1)
	embedded := make(chan pipeline.EmbeddedRecord, 1)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for job := range jobs {
			result := pipeline.FetchURL(ctx, job)
			fetched <- result
		}
		close(fetched)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		pipeline.RunExtractor(ctx, fetched, extracted, nil)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		pipeline.RunEmbedBatcher(ctx, cfg, extracted, embedded)
	}()

	jobs <- pipeline.CrawlJob{CveID: "CVE-2025-0001", URL: fetchSrv.URL, Domain: "test"}
	close(jobs)

	select {
	case result := <-embedded:
		if result.Job.CveID != "CVE-2025-0001" {
			t.Errorf("CveID not preserved: got %q", result.Job.CveID)
		}
		if result.Text == "" {
			t.Error("extracted text is empty")
		}
		if len(result.Embedding) != 1536 {
			t.Errorf("want 1536-dim vector, got %d", len(result.Embedding))
		}
	case <-ctx.Done():
		t.Fatal("pipeline timed out")
	}

	wg.Wait()
}

func TestPipeline_FetchErrorDoesNotBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	jobs := make(chan pipeline.CrawlJob, 1)
	fetched := make(chan pipeline.FetchResult, 1)
	extracted := make(chan pipeline.ExtractedText, 1)

	go func() {
		for job := range jobs {
			fetched <- pipeline.FetchURL(ctx, job)
		}
		close(fetched)
	}()

	go pipeline.RunExtractor(ctx, fetched, extracted, nil)

	jobs <- pipeline.CrawlJob{CveID: "CVE-2025-0002", URL: srv.URL, Domain: "test"}
	close(jobs)

	select {
	case _, ok := <-extracted:
		if ok {
			t.Error("expected no output for failed fetch")
		}
	case <-ctx.Done():
		t.Fatal("pipeline blocked on fetch error")
	}
}

func TestPipeline_MultipleJobsProcessed(t *testing.T) {
	fetchSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(sampleHTML)
	}))
	defer fetchSrv.Close()

	embedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(pipeline.EmbeddingResponse{
			Data: []pipeline.EmbeddingData{{Embedding: make([]float32, 1536)}},
		})
	}))
	defer embedSrv.Close()

	cfg := pipeline.Config{
		EmbedEndpoint: embedSrv.URL,
		OpenAIKey:     "test-key",
		EmbedModel:    "test-model",
		EmbedBatch:    1,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	jobs := make(chan pipeline.CrawlJob, 5)
	fetched := make(chan pipeline.FetchResult, 5)
	extracted := make(chan pipeline.ExtractedText, 5)
	embedded := make(chan pipeline.EmbeddedRecord, 5)

	go func() {
		for job := range jobs {
			fetched <- pipeline.FetchURL(ctx, job)
		}
		close(fetched)
	}()
	go pipeline.RunExtractor(ctx, fetched, extracted, nil)
	go pipeline.RunEmbedBatcher(ctx, cfg, extracted, embedded)

	numJobs := 5
	for i := 0; i < numJobs; i++ {
		jobs <- pipeline.CrawlJob{
			CveID:  "CVE-2025-" + string(rune('A'+i)),
			URL:    fetchSrv.URL,
			Domain: "test",
		}
	}
	close(jobs)

	received := 0
	for range embedded {
		received++
	}

	if received != numJobs {
		t.Errorf("want %d records, got %d", numJobs, received)
	}
}
