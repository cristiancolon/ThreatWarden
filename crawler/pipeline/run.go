package pipeline

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	pgxvec "github.com/pgvector/pgvector-go/pgx"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func Run(backfill bool) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	cfg := LoadConfig(backfill)

	if cfg.OpenAIKey == "" {
		slog.Error("OPENAI_API_KEY is required")
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		slog.Error("invalid database URL", "err", err)
		os.Exit(1)
	}

	poolCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		return pgxvec.RegisterTypes(ctx, conn)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		slog.Error("failed to connect to database", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		slog.Error("database ping failed", "err", err)
		os.Exit(1)
	}

	slog.Info("connected to database")

	jobs := make(chan CrawlJob, 1000)
	fetched := make(chan FetchResult, 500)
	extracted := make(chan ExtractedText, 500)
	embedded := make(chan EmbeddedRecord, 500)

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		RunDiscover(ctx, pool, cfg, jobs)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		router := NewDomainRouter(fetched, cfg.MaxDomains, cfg.DomainRate)
		router.Run(ctx, jobs)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		RunExtractor(ctx, fetched, extracted, pool)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		RunEmbedBatcher(ctx, cfg, extracted, embedded)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		RunWriter(ctx, pool, cfg, embedded)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		runMonitor(ctx)
	}()

	mode := "incremental"
	if cfg.Backfill {
		mode = "backfill"
	}
	slog.Info("crawler pipeline started", "mode", mode, "max_domains", cfg.MaxDomains, "embed_batch", cfg.EmbedBatch)

	wg.Wait()
	slog.Info("crawler pipeline stopped",
		"total_discovered", PipelineStats.Discovered.Load(),
		"total_stored", PipelineStats.Stored.Load(),
		"total_errors", PipelineStats.FetchErrors.Load(),
	)
}

func runMonitor(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			slog.Info("pipeline stats",
				"discovered", PipelineStats.Discovered.Load(),
				"fetched", PipelineStats.Fetched.Load(),
				"fetch_errors", PipelineStats.FetchErrors.Load(),
				"extracted", PipelineStats.Extracted.Load(),
				"embedded", PipelineStats.Embedded.Load(),
				"stored", PipelineStats.Stored.Load(),
			)
		case <-ctx.Done():
			return
		}
	}
}
