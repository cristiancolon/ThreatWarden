package pipeline

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const seedSQL = `
INSERT INTO crawl_progress (cve_id, url, domain)
SELECT r.cve_id, r.url, substring(r.url from 'https?://([^/]+)')
FROM cve_references r
LEFT JOIN crawl_progress cp ON cp.cve_id = r.cve_id AND cp.url = r.url
WHERE cp.id IS NULL
`

const claimSQL = `
UPDATE crawl_progress SET status = 'claimed'
WHERE id IN (
    SELECT cp.id
    FROM crawl_progress cp
    JOIN vulnerabilities v ON v.cve_id = cp.cve_id
    WHERE cp.status = 'pending'
    ORDER BY v.cisa_kev DESC, v.epss_score DESC NULLS LAST, v.cvss_score DESC NULLS LAST
    LIMIT $1
    FOR UPDATE SKIP LOCKED
)
RETURNING cve_id, url, domain
`

func SeedCrawlProgress(ctx context.Context, pool *pgxpool.Pool) (int64, error) {
	tag, err := pool.Exec(ctx, seedSQL)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func ClaimBatch(ctx context.Context, pool *pgxpool.Pool, limit int) ([]CrawlJob, error) {
	rows, err := pool.Query(ctx, claimSQL, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []CrawlJob
	for rows.Next() {
		var j CrawlJob
		if err := rows.Scan(&j.CveID, &j.URL, &j.Domain); err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

func RunDiscover(ctx context.Context, pool *pgxpool.Pool, cfg Config, out chan<- CrawlJob) {
	defer close(out)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		seeded, err := SeedCrawlProgress(ctx, pool)
		if err != nil {
			slog.Error("discover: seed failed", "err", err)
		} else if seeded > 0 {
			slog.Info("discover: seeded new URLs", "count", seeded)
		}

		jobs, err := ClaimBatch(ctx, pool, cfg.DiscoverBatch)
		if err != nil {
			slog.Error("discover: claim failed", "err", err)
			sleepCtx(ctx, 30*time.Second)
			continue
		}

		if len(jobs) == 0 {
			slog.Info("discover: no pending URLs, sleeping")
			sleepCtx(ctx, 5*time.Minute)
			continue
		}

		PipelineStats.Discovered.Add(int64(len(jobs)))
		slog.Info("discover: claimed batch", "count", len(jobs))

		for _, j := range jobs {
			select {
			case out <- j:
			case <-ctx.Done():
				return
			}
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-ctx.Done():
	}
}
