package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type embeddingRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

type EmbeddingData struct {
	Embedding []float32 `json:"embedding"`
}

type EmbeddingResponse struct {
	Data []EmbeddingData `json:"data"`
}

func EmbedTexts(endpoint, apiKey, model string, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, nil
	}

	reqBody, err := json.Marshal(embeddingRequest{Model: model, Input: texts})
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("embedding API %d: %s", resp.StatusCode, string(body))
	}

	var result EmbeddingResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}

	vectors := make([][]float32, len(result.Data))
	for i, d := range result.Data {
		vectors[i] = d.Embedding
	}
	return vectors, nil
}

func RunEmbedBatcher(ctx context.Context, cfg Config, in <-chan ExtractedText, out chan<- EmbeddedRecord) {
	defer close(out)

	var batch []ExtractedText
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}

		texts := make([]string, len(batch))
		for i, t := range batch {
			texts[i] = t.Text
		}

		vectors, err := EmbedTexts(cfg.EmbedEndpoint, cfg.OpenAIKey, cfg.EmbedModel, texts)
		if err != nil {
			slog.Error("embed batch failed, retrying", "err", err, "count", len(batch))
			vectors, err = EmbedTexts(cfg.EmbedEndpoint, cfg.OpenAIKey, cfg.EmbedModel, texts)
			if err != nil {
				slog.Error("embed retry failed, skipping batch", "err", err)
				batch = nil
				return
			}
		}

		for i, t := range batch {
			rec := EmbeddedRecord{Job: t.Job, Text: t.Text, Embedding: vectors[i]}
			select {
			case out <- rec:
				PipelineStats.Embedded.Add(1)
			case <-ctx.Done():
				return
			}
		}
		batch = nil
	}

	for {
		select {
		case t, ok := <-in:
			if !ok {
				flush()
				return
			}
			batch = append(batch, t)
			if len(batch) >= cfg.EmbedBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-ctx.Done():
			return
		}
	}
}
