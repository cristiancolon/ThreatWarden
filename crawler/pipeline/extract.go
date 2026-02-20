package pipeline

import (
	"bytes"
	"context"
	"log/slog"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/jackc/pgx/v5/pgxpool"
)

const MaxExtractLen = 50_000

func ExtractText(html []byte) string {
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(html))
	if err != nil {
		return ""
	}

	doc.Find("script, style, nav, header, footer, noscript, iframe").Remove()

	text := strings.TrimSpace(doc.Find("body").Text())

	fields := strings.Fields(text)
	text = strings.Join(fields, " ")

	if len(text) > MaxExtractLen {
		text = text[:MaxExtractLen]
	}

	return text
}

func RunExtractor(ctx context.Context, in <-chan FetchResult, out chan<- ExtractedText, pool *pgxpool.Pool) {
	defer close(out)

	for res := range in {
		if ctx.Err() != nil {
			return
		}

		PipelineStats.Fetched.Add(1)

		if res.Err != nil {
			slog.Warn("fetch failed", "url", res.Job.URL, "err", res.Err)
			PipelineStats.FetchErrors.Add(1)
			if pool != nil {
				markFailed(ctx, pool, res.Job)
			}
			continue
		}

		text := ExtractText(res.HTMLBody)
		if text == "" {
			slog.Debug("empty extraction", "url", res.Job.URL)
			if pool != nil {
				markFailed(ctx, pool, res.Job)
			}
			continue
		}

		PipelineStats.Extracted.Add(1)

		select {
		case out <- ExtractedText{Job: res.Job, Text: text}:
		case <-ctx.Done():
			return
		}
	}
}

func markFailed(ctx context.Context, pool *pgxpool.Pool, job CrawlJob) {
	_, err := pool.Exec(ctx, `
		UPDATE crawl_progress SET
			status = CASE WHEN attempts + 1 >= 3 THEN 'dead' ELSE 'pending' END,
			attempts = attempts + 1
		WHERE cve_id = $1 AND url = $2
	`, job.CveID, job.URL)
	if err != nil {
		slog.Error("mark failed", "url", job.URL, "err", err)
	}
}
