package pipeline

import "sync/atomic"

type CrawlJob struct {
	CveID  string
	URL    string
	Domain string
}

type FetchResult struct {
	Job      CrawlJob
	HTMLBody []byte
	Err      error
}

type ExtractedText struct {
	Job  CrawlJob
	Text string
}

type EmbeddedRecord struct {
	Job       CrawlJob
	Text      string
	Embedding []float32
}

type Stats struct {
	Discovered  atomic.Int64
	Fetched     atomic.Int64
	FetchErrors atomic.Int64
	Extracted   atomic.Int64
	Embedded    atomic.Int64
	Stored      atomic.Int64
}

var PipelineStats Stats
