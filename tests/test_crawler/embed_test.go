package test_crawler

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/threatwarden/crawler/pipeline"
)

// -- EmbedTexts ----------------------------------------------------------------

func TestEmbed_SendsCorrectRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("want POST, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer fake-key" {
			t.Errorf("bad auth header: %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("bad content type: %q", r.Header.Get("Content-Type"))
		}

		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		json.Unmarshal(body, &req)

		if req["model"] != "text-embedding-3-small" {
			t.Errorf("bad model: %v", req["model"])
		}
		inputs := req["input"].([]interface{})
		if len(inputs) != 2 {
			t.Errorf("want 2 inputs, got %d", len(inputs))
		}

		json.NewEncoder(w).Encode(pipeline.EmbeddingResponse{
			Data: []pipeline.EmbeddingData{
				{Embedding: []float32{0.1, 0.2, 0.3}},
				{Embedding: []float32{0.4, 0.5, 0.6}},
			},
		})
	}))
	defer srv.Close()

	vectors, err := pipeline.EmbedTexts(srv.URL, "fake-key", "text-embedding-3-small", []string{"text1", "text2"})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vectors) != 2 {
		t.Fatalf("want 2 vectors, got %d", len(vectors))
	}
	if vectors[0][0] != 0.1 {
		t.Errorf("want 0.1, got %f", vectors[0][0])
	}
}

func TestEmbed_ReturnsErrorOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error": "rate limited"}`))
	}))
	defer srv.Close()

	_, err := pipeline.EmbedTexts(srv.URL, "fake-key", "model", []string{"text"})
	if err == nil {
		t.Fatal("expected error for 429")
	}
}

func TestEmbed_HandlesEmptyInput(t *testing.T) {
	vectors, err := pipeline.EmbedTexts("http://unused", "key", "model", []string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if vectors != nil {
		t.Errorf("expected nil, got %v", vectors)
	}
}

func TestEmbed_ReturnsCorrectVectorCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(pipeline.EmbeddingResponse{
			Data: []pipeline.EmbeddingData{
				{Embedding: make([]float32, 1536)},
				{Embedding: make([]float32, 1536)},
				{Embedding: make([]float32, 1536)},
			},
		})
	}))
	defer srv.Close()

	vectors, err := pipeline.EmbedTexts(srv.URL, "key", "model", []string{"a", "b", "c"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vectors) != 3 {
		t.Fatalf("want 3 vectors, got %d", len(vectors))
	}
	if len(vectors[0]) != 1536 {
		t.Errorf("want 1536-dim vector, got %d", len(vectors[0]))
	}
}
