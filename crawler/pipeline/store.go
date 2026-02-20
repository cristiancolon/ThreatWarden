package pipeline

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pgvector/pgvector-go"
)

func StoreBatch(ctx context.Context, pool *pgxpool.Pool, records []EmbeddedRecord) error {
	if len(records) == 0 {
		return nil
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	batch := &pgx.Batch{}
	for _, rec := range records {
		vec := pgvector.NewVector(rec.Embedding)
		batch.Queue(`
			INSERT INTO advisory_content (cve_id, url, content, embedding)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (cve_id, url) DO UPDATE SET
				content = EXCLUDED.content, embedding = EXCLUDED.embedding, crawled_at = NOW()
		`, rec.Job.CveID, rec.Job.URL, rec.Text, vec)

		batch.Queue(`
			UPDATE crawl_progress SET status = 'complete'
			WHERE cve_id = $1 AND url = $2
		`, rec.Job.CveID, rec.Job.URL)
	}

	br := tx.SendBatch(ctx, batch)
	for i := 0; i < batch.Len(); i++ {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return fmt.Errorf("batch exec %d: %w", i, err)
		}
	}
	br.Close()

	return tx.Commit(ctx)
}

func RunWriter(ctx context.Context, pool *pgxpool.Pool, cfg Config, in <-chan EmbeddedRecord) {
	var batch []EmbeddedRecord
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := StoreBatch(ctx, pool, batch); err != nil {
			slog.Error("store batch failed", "err", err, "count", len(batch))
			for _, rec := range batch {
				_, _ = pool.Exec(ctx, `
					UPDATE crawl_progress SET status = 'pending'
					WHERE cve_id = $1 AND url = $2
				`, rec.Job.CveID, rec.Job.URL)
			}
		} else {
			PipelineStats.Stored.Add(int64(len(batch)))
			slog.Info("stored batch", "count", len(batch))
		}
		batch = nil
	}

	for {
		select {
		case rec, ok := <-in:
			if !ok {
				flush()
				return
			}
			batch = append(batch, rec)
			if len(batch) >= cfg.WriteBatch {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-ctx.Done():
			flush()
			return
		}
	}
}
