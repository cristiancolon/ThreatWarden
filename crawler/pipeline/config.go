package pipeline

import (
	"bufio"
	"os"
	"strings"
)

type Config struct {
	DatabaseURL   string
	OpenAIKey     string
	EmbedEndpoint string
	EmbedModel    string
	DiscoverBatch int
	EmbedBatch    int
	WriteBatch    int
	MaxDomains    int
	DomainRate    float64
	Backfill      bool
}

func LoadConfig(backfill bool) Config {
	loadDotEnv()

	cfg := Config{
		DatabaseURL:   getEnv("DB_URL", "postgresql://threatwarden:threatwarden@localhost:5432/threatwarden"),
		OpenAIKey:     getEnv("OPENAI_API_KEY", ""),
		EmbedEndpoint: getEnv("EMBED_ENDPOINT", "https://api.openai.com/v1/embeddings"),
		EmbedModel:    getEnv("EMBED_MODEL", "text-embedding-3-small"),
		DiscoverBatch: 500,
		EmbedBatch:    50,
		WriteBatch:    500,
		MaxDomains:    200,
		DomainRate:    2.0,
		Backfill:      backfill,
	}

	if backfill {
		cfg.DiscoverBatch = 5000
		cfg.MaxDomains = 500
	}

	return cfg
}

func loadDotEnv() {
	for _, path := range []string{".env", "../.env"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			if _, exists := os.LookupEnv(strings.TrimSpace(k)); !exists {
				os.Setenv(strings.TrimSpace(k), strings.TrimSpace(v))
			}
		}
		f.Close()
		return
	}
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}
