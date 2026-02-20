package pipeline

import (
	"context"
	"log/slog"
	"sync"

	"golang.org/x/time/rate"
)

type DomainRouter struct {
	mu      sync.Mutex
	workers map[string]chan CrawlJob
	out     chan<- FetchResult
	rate    float64
	sem     chan struct{}
	wg      sync.WaitGroup
}

func NewDomainRouter(out chan<- FetchResult, maxDomains int, ratePerSec float64) *DomainRouter {
	return &DomainRouter{
		workers: make(map[string]chan CrawlJob),
		out:     out,
		rate:    ratePerSec,
		sem:     make(chan struct{}, maxDomains),
	}
}

func (r *DomainRouter) Run(ctx context.Context, in <-chan CrawlJob) {
	for job := range in {
		if ctx.Err() != nil {
			break
		}
		r.route(ctx, job)
	}

	r.mu.Lock()
	for _, ch := range r.workers {
		close(ch)
	}
	r.mu.Unlock()

	r.wg.Wait()
	close(r.out)
}

func (r *DomainRouter) route(ctx context.Context, job CrawlJob) {
	r.mu.Lock()
	ch, exists := r.workers[job.Domain]
	if !exists {
		ch = make(chan CrawlJob, 100)
		r.workers[job.Domain] = ch
		r.wg.Add(1)
		go r.domainWorker(ctx, job.Domain, ch)
	}
	r.mu.Unlock()

	select {
	case ch <- job:
	case <-ctx.Done():
	}
}

func (r *DomainRouter) domainWorker(ctx context.Context, domain string, in <-chan CrawlJob) {
	defer r.wg.Done()

	r.sem <- struct{}{}
	defer func() { <-r.sem }()

	limiter := rate.NewLimiter(rate.Limit(r.rate), 1)

	slog.Debug("router: started worker", "domain", domain)

	for job := range in {
		if ctx.Err() != nil {
			return
		}
		_ = limiter.Wait(ctx)
		result := FetchURL(ctx, job)
		select {
		case r.out <- result:
		case <-ctx.Done():
			return
		}
	}
}
