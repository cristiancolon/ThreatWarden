package main

import (
	"flag"

	"github.com/threatwarden/crawler/pipeline"
)

func main() {
	backfill := flag.Bool("backfill", false, "run in backfill mode with higher concurrency")
	flag.Parse()

	pipeline.Run(*backfill)
}
