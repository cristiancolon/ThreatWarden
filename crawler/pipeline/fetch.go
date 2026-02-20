package pipeline

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

func FetchURL(ctx context.Context, job CrawlJob) FetchResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, job.URL, nil)
	if err != nil {
		return FetchResult{Job: job, Err: fmt.Errorf("build request: %w", err)}
	}
	req.Header.Set("User-Agent", "ThreatWarden-Crawler/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		return FetchResult{Job: job, Err: fmt.Errorf("fetch: %w", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return FetchResult{Job: job, Err: fmt.Errorf("HTTP %d for %s", resp.StatusCode, job.URL)}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return FetchResult{Job: job, Err: fmt.Errorf("read body: %w", err)}
	}

	return FetchResult{Job: job, HTMLBody: body}
}
