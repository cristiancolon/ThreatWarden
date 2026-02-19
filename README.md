# ThreatWarden

## 1. Overview

ThreatWarden is a continuously-running vulnerability intelligence system that aggregates exploit and CVE data from authoritative sources, stores it in PostgreSQL, and exposes that knowledge through a conversational LLM interface. The goal is to let a developer ask natural-language questions about vulnerabilities relevant to their stack and get grounded, cited, prioritized answers.

Development is split into phases:

- **Phase 1:** Structured data ingestion pipeline + SQL-based query interface with LLM synthesis. The LLM parses user questions into structured SQL filters; results are assembled into context and synthesized into natural-language answers. No embeddings needed — vulnerability data is highly structured and SQL handles it precisely.
- **Phase 1.5:** Web crawler enrichment + pgvector. A crawler augments CVE records with external advisory content (vendor blogs, PoC READMEs, remediation guides). This rich prose makes semantic search valuable, so pgvector is added for queries that can't be decomposed into SQL filters.
- **Phase 2:** Codebase-aware intelligence — dependency scanning, continuous monitoring, contextual alerting, and a web interface. The differentiator from existing SCA tools (Dependency-Track, OSV-Scanner) is that ThreatWarden's alerts include LLM-synthesized context: not just "CVE-X affects package-Y" but "here's what it means, how serious it is, and what to do."

This document covers Phase 1 in detail and outlines Phase 1.5. Phase 2 is previewed at the end.

---

## 2. Problem Statement

Security vulnerability data is fragmented across dozens of sources (NVD, GitHub Advisories, CISA KEV, Exploit-DB, EPSS feeds). A developer who wants to understand their exposure must manually cross-reference CVE databases, check exploit maturity, parse CVSS scores, and read advisory prose. This is tedious, error-prone, and rarely done proactively.

ThreatWarden solves this by:

1. Continuously aggregating and normalizing vulnerability data from structured feeds.
2. Enriching that data with exploit maturity signals (PoC availability, KEV inclusion, EPSS probability).
3. Making the full corpus queryable via natural language through an LLM grounded in the collected data.

### 2.1 Landscape & Differentiation

Several projects occupy adjacent parts of this space:

- **[OSV.dev](https://osv.dev/) (Google)** — Distributed vulnerability database aggregating 40+ ecosystems with a standardized schema. Excellent data layer and API, but no natural language interface or LLM synthesis.
- **[CVE.ICU](https://cve.icu/)** — Open-source analytics dashboard for CVE trends and statistics. Visualization, not querying.
- **[BRON](http://bron.alfa.csail.mit.edu/info.html) (MIT CSAIL)** — Knowledge graph linking ATT&CK, CAPEC, CWE, and CVE for academic ML research. Not developer-facing, not real-time.
- **[Dependency-Track](https://dependencytrack.org/) (OWASP)** — Enterprise SCA platform with SBOM analysis, policy engines, and alerting. Powerful but heavy, no conversational interface.
- **[ProveRAG](https://arxiv.org/abs/2410.17406) (RIT, 2024)** — Research prototype using LLM + RAG for single-CVE deep analysis with self-critique provenance. Analyst-focused, stateless (fetches from web at query time), no persistent corpus.
- **[Vulnrichment](https://github.com/cisagov/vulnrichment) (CISA)** — Enriches CVE records with SSVC and CVSS upstream; data already flows into NVD.

**Where ThreatWarden fits:** No existing tool combines a continuously-updated multi-source corpus with a natural language interface for developers. The data aggregation problem is largely solved (OSV, NVD). The value ThreatWarden creates is in the **interface layer** — turning fragmented structured data into conversational, prioritized, actionable answers with verified citations. ThreatWarden should consume existing data sources (including OSV.dev) rather than compete on aggregation, and borrow ProveRAG's self-critique pattern to ensure answer reliability.

---

## 3. Goals & Non-Goals

### Goals

- Ingest CVE/advisory data from at least four authoritative sources on an automated schedule.
- Store structured vulnerability records in PostgreSQL with proper relational modeling.
- (Phase 1.5) Enrich records with crawled advisory content and store as vector embeddings for semantic retrieval.
- Provide a conversational interface where a user can ask questions about vulnerabilities, packages, or ecosystems and receive grounded answers with citations.
- Deduplicate and update records as sources publish revisions.
- Track exploit maturity: flag when a CVE has a known public exploit, a Metasploit module, or appears on CISA's Known Exploited Vulnerabilities catalog.

### Non-Goals (Phase 1)

- Codebase or dependency scanning (Phase 2a).
- Continuous project monitoring and alerting (Phase 2b).
- Web UI or API server (Phase 2c). CLI only in Phase 1.
- ATT&CK mapping or threat context enrichment (Phase 2d).
- Static analysis / insecure code pattern detection (Phase 2d, stretch).
- Custom-trained or fine-tuned models (we use off-the-shelf embeddings and LLMs via API).

---

## 4. Users & Personas

| Persona | Description | Primary Use |
|---|---|---|
| **Solo Developer** | Works on side projects, wants a quick "am I affected?" check. | Asks about specific packages or CVEs by name. |
| **Security-Curious Engineer** | Wants to stay informed about emerging threats relevant to their ecosystem. | Asks broad ecosystem questions ("anything new affecting npm this week?"). |
| **The Builder (You)** | Learning security tooling, building portfolio project with real utility. | Operates, extends, and iterates on the system. |

---

## 5. System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Ingestion Service                     │
│                  (asyncio scheduler)                    │
│                                                         │
│  ┌───────────┐ ┌──────────┐ ┌────────┐ ┌──────────┐     │
│  │    NVD    │ │  GitHub  │ │  CISA  │ │   EPSS   │     │
│  │ Ingestor  │ │ Ingestor │ │  KEV   │ │ Ingestor │     │
│  │(fetch +   │ │(fetch +  │ │Ingestor│ │          │     │
│  │normalize) │ │normalize)│ │        │ │          │     │
│  └─────┬─────┘ └────┬─────┘ └───┬────┘ └────┬─────┘     │
│        │             │           │            │         │
│        └──────┬──────┴─────┬─────┴────────────┘         │
│               │            │                            │
│         ┌─────▼────────────▼────┐                       │
│         │  db/writer.py         │                       │
│         │  (upsert + COALESCE)  │                       │
│         └───────────┬───────────┘                       │
└─────────────────────┼───────────────────────────────────┘
                      │
              ┌───────▼────────┐
              │   PostgreSQL   │
              │  (relational)  │
              └───────┬────────┘
                      │
              ┌───────▼────────┐
              │   Query Engine │
              │  (intent →     │
              │   SQL → LLM)   │
              └───────┬────────┘
                      │
              ┌───────▼────────┐
              │   CLI / Chat   │
              │   Interface    │
              └────────────────┘

Phase 1.5 additions (dotted lines = new components):

              ┌─────────────────┐
              │   Web Crawler   │ ·········> enriches CVE records
              │  (vendor blogs, │            with advisory prose
              │   PoC READMEs)  │
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │   PostgreSQL    │
              │  (relational    │
              │  + pgvector)    │
              └────────┬────────┘
                       │
              ┌────────▼────────┐
              │  Query Engine   │
              │  (SQL + vector  │ ·········> semantic path added
              │    search)      │
              └─────────────────┘
```

---

## 6. Component Specifications

### 6.1 Ingestion Service

The ingestion service is a long-running process that periodically fetches vulnerability data from external sources, normalizes it, and writes it to PostgreSQL.

#### 6.1.1 Data Sources

Each source is implemented as an independent **Ingestor** class (one file per source) that handles both fetching and normalizing. This makes it straightforward to add new sources later.

| Source | Method | Frequency | Data Provided | Priority |
|---|---|---|---|---|
| **NVD (National Vulnerability Database)** | REST API v2.0 (`api.nvd.nist.gov`) | Every 2 hours | CVE records, CVSS v3.1 scores, CPE match strings, descriptions, references, CISA KEV flags | P0 — primary CVE source |
| **GitHub Security Advisories** | REST API (`api.github.com/advisories`) | Every 2 hours | Package-level vulnerability mappings (ecosystem, package name, vulnerable version ranges, patched versions), CVSS via `cvss_severities`, EPSS scores | P0 — best for dependency-level matching |
| **CISA KEV** | Static JSON download (`cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`) | Daily | Confirmed actively-exploited CVE IDs, due dates, required actions | P0 — critical severity signal |
| **EPSS (Exploit Prediction Scoring System)** | CSV download (`epss.cyentia.com`) | Daily | Probability score (0–1) that a CVE will be exploited in the next 30 days, percentile | P1 — prioritization signal |
| **Exploit-DB** | Git mirror clone + CSV index (`gitlab.com/exploit-database/exploitdb`) | Daily | Proof-of-concept exploit code, metadata, linked CVEs | P1 — exploit maturity signal |
| **OSV.dev** | REST API (`api.osv.dev`) | Every 2 hours | Standardized vulnerability records across 40+ ecosystems, precise affected version ranges per package | P1 — supplements NVD/GitHub with broader ecosystem coverage and machine-readable version constraints |

**Note:** The GitHub Advisory REST API deprecated the `cvss` field in April 2025, replacing it with `cvss_severities` (separate `cvss_v3` and `cvss_v4` objects). The API also provides EPSS data directly. References are returned as plain URL strings, not objects.

**Note:** NVD CVE records include CISA KEV data directly (`cisaActionDue`, `cisaRequiredAction`, etc.) when a CVE is in the KEV catalog, reducing the need for a separate CISA fetch for those CVEs.

**Note:** OSV.dev aggregates data from GitHub Security Advisories, PyPA, RustSec, and many other ecosystem-specific databases. Its version range format is machine-readable and standardized (OpenSSF OSV schema), making it potentially more reliable for version matching than parsing NVD's CPE strings. Its API has no rate limits.

#### 6.1.2 Ingestor Interface

Each source is implemented as a single Ingestor class that handles both fetching and normalizing. This collocates the API-specific fetch logic with the API-specific data mapping, avoiding a shared normalizer that would inevitably become a switch statement over source types.

```python
class Ingestor(ABC):
    @abstractmethod
    async def fetch_updates(self, since: datetime | None) -> list[RawVulnerability]:
        """
        Fetch new or updated vulnerability records since the given timestamp.
        If `since` is None, perform a full initial sync.
        """

    @abstractmethod
    def source_name(self) -> str:
        """Return the canonical name of this source (e.g., 'nvd', 'github')."""

    @abstractmethod
    def _normalize(self, raw: dict[str, Any]) -> NormalizedVulnerability:
        """Convert a single raw API response dict into a NormalizedVulnerability."""

    def normalize_updates(self, raw_updates: list[dict[str, Any]]) -> list[NormalizedVulnerability]:
        """Concrete method — maps _normalize over a list."""
        return [self._normalize(raw) for raw in raw_updates]
```

Each ingestor handles its own pagination, rate limiting, retry logic, and normalization. The `_normalize` method is where each source's unique response structure is mapped to the common `NormalizedVulnerability` output. `normalize_updates` is a concrete method on the base class since the iteration logic is identical across all subclasses.

Shared utilities (`get_response_with_retry`, data classes) live in `ingestion/base.py`. Source-specific helpers (e.g., GitHub's `parse_next_url`) live in their respective ingestor modules.

#### 6.1.3 Normalization

Normalization is handled per-ingestor via the `_normalize` method rather than a shared normalizer module. Each source's raw API response has a completely different structure:

- **NVD:** Deeply nested JSON (`metrics.cvssMetricV31[0].cvssData.baseScore`). Extracts CVSS (preferring v3.1 > v4.0 > v2, preferring Primary source), English description, dates, CISA KEV status, and reference URLs with tag mapping.
- **GitHub:** Flatter JSON. Primary value is the `vulnerabilities` array → `AffectedPackage` objects. Uses `cvss_severities` (not the deprecated `cvss` field). Normalizes EPSS from 0–100 scale to 0–1. References are plain URL strings.
- **CISA KEV / EPSS / Exploit-DB:** Each has its own minimal response structure.

This separation means an API schema change in one source only requires editing one file. A change to the internal `NormalizedVulnerability` structure only requires updating the `_normalize` methods.

#### 6.1.4 Deduplication

Deduplication is handled at the database level via `INSERT ... ON CONFLICT` (upsert) with no application-level state.

- **Primary dedup key:** `cve_id` on the `vulnerabilities` table.
- **Multi-source merging via COALESCE:** Each source fills its fields without nulling out fields from other sources. E.g., `cvss_score = COALESCE(EXCLUDED.cvss_score, vulnerabilities.cvss_score)` means "use the new value if non-null, otherwise keep what's there."
- **KEV flag is sticky:** `cisa_kev = EXCLUDED.cisa_kev OR vulnerabilities.cisa_kev` — once true, stays true. Prevents sources that don't know about KEV status from resetting it.
- **Source accumulation:** `raw_sources` array merges and deduplicates across syncs.
- **Sub-record isolation:** `affected_packages` and `exploits` use unique constraints that include `source`, so each source owns its own rows and can only overwrite its own data via `ON CONFLICT`.
- **High-water mark:** The `sync_metadata` table tracks the last successful sync timestamp per source. This determines the `since` parameter for the next fetch. Only updated after a successful transaction.

All write operations live in `db/writer.py` as stateless functions that take an asyncpg connection. No deduplicator class — the database is the single source of truth.

#### 6.1.5 Scheduling

The scheduler uses plain **asyncio** rather than APScheduler. Each ingestor runs as an independent `asyncio` task with its own sleep interval. This eliminates an external dependency for functionality that amounts to "run a function, sleep, repeat."

- Each task: read high-water mark → fetch (HTTP, no DB held) → normalize → write (single transaction) → update high-water mark → sleep.
- Configurable intervals via environment variables (`FAST_INTERVAL`, `DAILY_INTERVAL`).
- Default schedule: NVD + GitHub every 2 hours, CISA KEV + EPSS + Exploit-DB daily.
- `asyncio.TaskGroup` runs all tasks concurrently with failure isolation — one source failing does not affect others.
- On first run, `sync_metadata` returns `None` for the high-water mark, causing `fetch_updates(None)` to perform a full historical sync.
- Crash recovery is automatic: if a sync fails mid-batch, the transaction rolls back and the high-water mark is not updated, so the next cycle re-fetches the same window. Upserts are idempotent, so re-processing is safe.

#### 6.1.6 Rate Limiting & Resilience

- NVD: honor 50 requests/30s with API key (5 requests/30s without). Obtain a free API key.
- GitHub: 5,000 requests/hour with PAT. Use Link header pagination.
- Exponential backoff with doubling delay on transient failures (HTTP 429, 5xx), implemented in `get_response_with_retry`.
- Each ingestor task catches exceptions, logs them, and continues to the next cycle. A single source failure never blocks other sources.

---

### 6.2 Data Storage — PostgreSQL

#### 6.2.1 Schema

The authoritative schema lives in `src/db/schema.sql`. All tables use `CREATE TABLE IF NOT EXISTS` so the init function can run on every startup safely.

```sql
CREATE TABLE IF NOT EXISTS sync_metadata (
    source_name TEXT PRIMARY KEY,
    last_successful_sync TIMESTAMP WITH TIME ZONE,
    last_cursor TEXT,
    records_synced INTEGER DEFAULT 0,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    cvss_score FLOAT,
    cvss_vector TEXT,
    cvss_version TEXT,
    epss_score FLOAT,
    epss_percentile FLOAT,
    cisa_kev BOOLEAN DEFAULT FALSE,
    cisa_kev_due_date DATE,
    severity TEXT,
    published_at TIMESTAMP WITH TIME ZONE,
    modified_at TIMESTAMP WITH TIME ZONE,
    created_in_db TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_in_db TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    raw_sources TEXT[]
);

CREATE TABLE IF NOT EXISTS affected_packages (
    id SERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    package_name TEXT NOT NULL,
    vulnerable_versions TEXT,
    patched_version TEXT,
    source TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (cve_id, ecosystem, package_name, source)
);

CREATE TABLE IF NOT EXISTS exploits (
    id SERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    source_id TEXT NOT NULL DEFAULT '',
    url TEXT,
    description TEXT,
    discovered_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (cve_id, source, source_id)
);

CREATE TABLE IF NOT EXISTS cve_references (
    id SERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    ref_type TEXT,
    source TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (cve_id, url)
);
```

#### 6.2.2 Key Design Decisions

- **CVE as spine:** Every record ultimately links back to a `cve_id`. This is the universal join key across all sources.
- **Multi-source merging:** The `raw_sources` array on `vulnerabilities` tracks which feeds contributed data. Sub-tables (`affected_packages`, `exploits`) track source per row with unique constraints to prevent duplicates.
- **`description` is nullable:** Not every source provides a description on first contact with a CVE. COALESCE fills it in when a source that has one syncs later.
- **`exploits.source_id` is `NOT NULL DEFAULT ''`:** PostgreSQL treats `NULL != NULL`, which would break the unique constraint. Using an empty string default ensures the constraint works for exploits without a source-specific ID.
- **`cve_references` has `UNIQUE (cve_id, url)`:** Not in the original design, but required for idempotent upserts on references.
- **Soft deletion not needed:** CVEs are never deleted, only updated. If NVD rejects a CVE, mark it with a `REJECTED` status rather than removing.

---

### 6.3 Web Crawler & Vector Embeddings — Phase 1.5

This section is **not part of Phase 1**. It documents the design for Phase 1.5, which adds semantic search capability on top of the structured data pipeline.

#### 6.3.1 Why Phase 1.5 and Not Phase 1

In Phase 1, the data we ingest is highly structured: CVE IDs, CVSS scores, version ranges, severity levels, ecosystems. An LLM can parse a user's question into SQL filters that query this data precisely. Embedding one-line CVE descriptions into a vector store adds marginal value — the descriptions are formulaic and short ("Buffer overflow in libfoo allows remote code execution").

The vector store becomes valuable when there is **rich, unstructured prose** to embed: vendor blog posts explaining the vulnerability in context, PoC READMEs, detailed remediation guides, community write-ups. That content doesn't exist in the structured feeds — it comes from crawling reference URLs.

**The crawler creates the content that makes vector search valuable.** Therefore, vector embeddings follow the crawler, not the other way around.

#### 6.3.2 Web Crawler

The crawler enriches existing CVE records by fetching content from reference URLs already stored in `cve_references`.

**Crawl targets** (prioritized):
1. Vendor advisory pages linked in NVD/GitHub references.
2. GitHub security advisory detail pages.
3. Blog posts and write-ups from security researchers.
4. Exploit-DB PoC descriptions and READMEs.

**Crawl strategy:**
- Start from URLs already in `cve_references` — no discovery needed, the ingestion pipeline provides the seed list.
- Use `httpx` with a headless fallback (e.g., Playwright) for JS-rendered pages.
- Extract main content (strip nav, ads, boilerplate) using a readability parser.
- Rate-limit per domain to be a good citizen.
- Store crawled content in a `crawled_content` table linked to `cve_id`.

**Crawled content schema:**

```sql
CREATE TABLE IF NOT EXISTS crawled_content (
    id SERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    title TEXT,
    content TEXT NOT NULL,
    content_type TEXT NOT NULL,   -- 'vendor_advisory', 'blog_post', 'poc_readme', etc.
    crawled_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (cve_id, url)
);
```

#### 6.3.3 LLM Summarization (Summarize-then-Embed)

Raw crawled content is noisy — boilerplate, navigation remnants, tangential paragraphs. ProveRAG's research found that **LLM-based summarization significantly outperforms raw chunking** for vulnerability data (30%+ improvement in mitigation accuracy over traditional chunk-and-embed RAG). We adopt this finding.

Instead of chunking raw crawled pages and embedding the chunks directly, the enrichment pipeline runs as **three independent stages**, each using the database as a work queue:

1. **Crawl stage** — Fetch reference URLs, extract article text, write `raw_content` to `crawled_content`. No LLM calls. Runs at crawl rate limits.
2. **Summarize stage** — Find rows where `summary IS NULL`, call LLM to produce vulnerability-focused summaries, write `summary` + `summarized_at`. Runs at LLM API throughput.
3. **Embed stage** — Find summarized rows with no corresponding `embeddings` entry, embed the summary, upsert to `embeddings`. Runs at embedding API throughput.

Each stage is independent and idempotent. If OpenAI is down, crawling still progresses. If crawling is slow, previously-crawled content still gets summarized and embedded. The database is the boundary between stages — `summary IS NULL` is the summarization work queue, a LEFT JOIN to `embeddings` where `embeddings.id IS NULL` is the embedding work queue.

This produces higher-quality embeddings because summaries are dense, relevant, and stripped of noise. It also reduces vector count — one summary per crawled page instead of multiple overlapping chunks.

**Summarization prompt:**

```
Given the following web page content about a security vulnerability:
[crawled content]

Summarize the vulnerability-relevant information:
1. What is the vulnerability and what does it affect?
2. How can it be exploited?
3. What is the recommended remediation or workaround?
4. What specific versions, platforms, or configurations are affected?

Only include information present in the content. If a section has no relevant information, omit it.
```

**Summarization model:** Same lightweight model as intent parsing (`gpt-4.1-mini`). Summaries are short and factual — no need for the full synthesis model.

**Updated crawled_content schema:**

```sql
CREATE TABLE IF NOT EXISTS crawled_content (
    id SERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    title TEXT,
    raw_content TEXT NOT NULL,       -- original extracted text
    summary TEXT,                    -- LLM-generated vulnerability summary
    content_type TEXT NOT NULL,      -- 'vendor_advisory', 'blog_post', 'poc_readme', etc.
    crawled_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    summarized_at TIMESTAMP WITH TIME ZONE,
    UNIQUE (cve_id, url)
);
```

#### 6.3.4 Vector Embeddings (pgvector)

Once summaries exist, they are embedded into pgvector.

**Technology choice:** pgvector (PostgreSQL extension) instead of a dedicated vector store.

Rationale:
- **Scale fits:** With summarize-then-embed, vector count is lower (~1 per crawled page, not multiple chunks). pgvector with HNSW handles millions comfortably.
- **Atomic consistency:** Vector upserts live in the same transaction as relational upserts.
- **Filtered search uses real SQL:** Filters on ecosystem, severity, date range use normal WHERE/JOIN over indexed columns.
- **One fewer service:** No separate container to deploy, monitor, or back up.

**What gets embedded:**

| Content Type | Source | Strategy |
|---|---|---|
| Summarized vendor advisories and blog posts | `crawled_content.summary` | One embedding per summary. |
| Summarized exploit descriptions | Exploit-DB (crawled + summarized) | One embedding per exploit summary. |
| Extended CVE descriptions (when substantial) | NVD, GitHub Advisory | Only if description > 200 tokens. Embedded directly (already concise). |

**Embedding model:** OpenAI `text-embedding-3-small` (1536 dimensions). Can swap to a local model (e.g., `nomic-embed-text` via Ollama) later if cost is a concern.

**Storage:**

```sql
CREATE TABLE IF NOT EXISTS embeddings (
    id SERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    source_type TEXT NOT NULL,       -- 'crawled_summary', 'cve_description', etc.
    source_id INTEGER,               -- FK to crawled_content.id (nullable for CVE descriptions)
    content TEXT NOT NULL,            -- the text that was embedded (summary, not raw)
    embedding vector(1536) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE (cve_id, source_type, source_id)
);

CREATE INDEX IF NOT EXISTS idx_embeddings_hnsw ON embeddings
    USING hnsw (embedding vector_cosine_ops);
```

**Stage coordination:**

The three stages can run as independent asyncio tasks in the scheduler (same pattern as Phase 1 ingestors), each with its own interval:

| Stage | Work queue | Interval | Rate limit |
|---|---|---|---|
| Crawl | `cve_references` URLs not in `crawled_content` | 12 hours | 2 req/sec per domain |
| Summarize | `crawled_content` rows where `summary IS NULL` | 1 hour | OpenAI token throughput |
| Embed | Summarized rows with no `embeddings` entry | 1 hour | OpenAI embedding throughput |

The summarize and embed stages run more frequently than the crawl stage because they're catching up on newly-crawled content. Once there's no pending work, they're no-ops.

Re-crawling: when a page's content changes (detected by content hash), `raw_content` is updated and `summary` is set to NULL, which re-queues it through the summarize → embed pipeline. The unique constraints enable idempotent upserts throughout.

---

### 6.4 Query Engine

#### 6.4.1 Phase 1 — SQL-Based Query Flow

In Phase 1, all retrieval is SQL-based. The LLM's role is to parse intent, synthesize answers, and verify its own output.

```
User Question
     │
     ▼
┌──────────────────┐
│  Intent Parser   │  ← LLM call (gpt-4.1-mini) to extract structured filters
│                  │     (ecosystem, packages, severity, date range, CVE IDs)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  SQL Query       │  ← Parameterized query against PostgreSQL using filters
│  Builder         │     JOINs vulnerabilities + affected_packages + exploits
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Context         │  ← Formats matching rows into structured text blocks
│  Assembly        │     Ranks and truncates to fit token budget
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  LLM Synthesis   │  ← Generates natural-language answer grounded in SQL results
│                  │     Includes citations (CVE IDs, source URLs)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Verification    │  ← LLM checks each claim against the retrieved context
│                  │     Flags unsupported claims, fills omissions
└──────────────────┘
```

This works well for Phase 1 because vulnerability data is inherently structured. Questions like "Is Flask 2.0.1 vulnerable to anything critical?" decompose cleanly into SQL: filter `affected_packages` by ecosystem/name, JOIN to `vulnerabilities` WHERE severity = 'CRITICAL'. No embeddings needed.

#### 6.4.2 Phase 1.5 — Adding Semantic Search

Once the web crawler (Section 6.3) populates `crawled_content` and `embeddings`, a second retrieval path is added:

```
User Question
     │
     ▼
┌──────────────────┐
│  Intent Parser   │  ← Extracts structured filters + cleaned search query
└────────┬─────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌────────┐ ┌──────────────┐
│  SQL   │ │ Vector Search│  ← Cosine similarity on embeddings table
│  Query │ │ (pgvector)   │     Filtered via SQL WHERE/JOIN on structured columns
└───┬────┘ └──────┬───────┘
    │              │
    └──────┬───────┘
           ▼
┌──────────────────┐
│  Merge + Rank    │  ← Deduplicate by cve_id, rank by severity signals
└────────┬─────────┘
         ▼
┌──────────────────┐
│  Context Assembly│
└────────┬─────────┘
         ▼
┌──────────────────┐
│  LLM Synthesis   │
└────────┬─────────┘
         ▼
┌──────────────────┐
│  Verification    │  ← Same self-critique as Phase 1, now with richer context
└──────────────────┘
```

The semantic path handles queries that don't decompose into SQL filters: "What vulnerabilities involve authentication bypass in web frameworks?" has no clean column to filter on — it needs similarity search over advisory prose.

#### 6.4.3 Intent Parsing

Before searching, the user's question is passed through an LLM call (lightweight model — e.g., `gpt-4.1-mini`) with a structured output schema:

```python
class QueryIntent(BaseModel):
    ecosystems: list[str] | None        # e.g., ['pypi', 'npm']
    package_names: list[str] | None     # e.g., ['flask', 'requests']
    cve_ids: list[str] | None           # e.g., ['CVE-2025-1234']
    severity_filter: str | None         # e.g., 'CRITICAL', 'HIGH+'
    date_range: str | None              # e.g., 'last 30 days'
    query_type: str                     # 'specific_cve', 'package_check', 'general_search'
    raw_search_query: str               # cleaned/rephrased query for vector search (Phase 1.5)
```

In Phase 1, only the structured fields are used. `raw_search_query` is generated but ignored until Phase 1.5 adds the vector path.

#### 6.4.4 Retrieval Strategy

**Phase 1 (SQL only):**

If the intent parser extracts specific packages, CVE IDs, ecosystems, severity levels, or date ranges, query PostgreSQL directly with parameterized SQL. This gives exact, reliable results for the types of queries Phase 1 supports.

**Phase 1.5 (SQL + vector):**

1. **Structured path:** Same SQL queries as Phase 1.
2. **Semantic path:** Embed `raw_search_query`, run filtered cosine similarity against `embeddings` table. Filters applied via SQL WHERE/JOIN on `vulnerabilities` columns. Top-k = 10.
3. **Merge:** Combine both result sets, deduplicate by `cve_id`, rank by relevance weighted by severity signals (EPSS, KEV, exploit availability).

#### 6.4.5 Context Assembly

Format each retrieved CVE as a structured text block:

```
[CVE-2025-1234] (CRITICAL | CVSS 9.8 | EPSS 0.87 | KEV: Yes | Exploit: Yes)
Affects: flask (pypi) versions >=2.0.0 <2.3.1 — patched in 2.3.1
Description: <from DB in Phase 1 / from crawled content in Phase 1.5>
Sources: https://nvd.nist.gov/vuln/detail/CVE-2025-1234
```

- Total context budget: ~15,000 tokens of retrieved content (leaving room for system prompt + user question + response). The larger budget accommodates Phase 1.5 semantic search results (crawled articles, exploit write-ups) alongside structured CVE blocks.
- If over budget, prioritize by: KEV status > has-exploit > EPSS score > CVSS score > recency.

#### 6.4.6 LLM Synthesis

- **Model:** Configurable (e.g., GPT-5.2, Claude Sonnet).
- **System prompt** instructs the model to:
  - Only answer based on the provided context.
  - Always cite CVE IDs.
  - Clearly state when no relevant vulnerabilities were found.
  - Recommend specific actions (upgrade to version X, apply workaround Y).
  - Flag exploit maturity clearly ("a public PoC exists," "actively exploited per CISA").
- **Temperature:** 0.1 (factual, low creativity).

#### 6.4.7 Verification (Self-Critique)

Inspired by [ProveRAG](https://arxiv.org/abs/2410.17406) (Fayyazi et al., 2024), the query engine includes a verification pass after synthesis. ProveRAG demonstrated that LLM self-critique with provenance tracking achieves 99% accuracy on exploitation strategies and 97% on mitigation — significantly outperforming unverified generation.

**How it works:**

After the synthesis LLM generates a response, a verification call (using the same lightweight model as intent parsing, e.g., `gpt-4.1-mini`) receives:
1. The original SQL context (the structured text blocks that were provided to the synthesis model).
2. The generated response.

The verifier classifies each factual claim in the response as:

- **Supported:** Claim is backed by the provided context. The verifier cites the specific context block.
- **Unsupported:** Claim appears in the response but has no backing in the context — potential hallucination. Stripped or flagged.
- **Omitted:** Important information exists in the context but was not mentioned in the response. Appended as a note.

**Verification prompt structure:**

```python
class VerifiedClaim(BaseModel):
    claim: str
    status: str          # 'supported', 'unsupported', 'omitted'
    evidence: str | None # the context line that supports/contradicts the claim
    rationale: str       # why this classification was made

class VerificationResult(BaseModel):
    claims: list[VerifiedClaim]
    omissions: list[str] # important context not reflected in the response
```

**Why this is cheap:** The verification model is the lightweight intent model (`gpt-4.1-mini`), not the full synthesis model. The input is small (the already-assembled context + the response). In practice this adds one fast LLM call per query — negligible latency compared to the synthesis call.

**What it catches:**
- Hallucinated CVE IDs (cited a CVE not in the context).
- Wrong version ranges or patched versions.
- Missed KEV/exploit flags that were in the context but omitted from the response.
- Fabricated remediation advice not grounded in the data.

The final output shown to the user is the synthesis response with unsupported claims removed and omissions appended. If the verifier flags issues, the response is annotated rather than silently modified.

#### 6.4.8 Example Interactions

**Query:** "Is Flask 2.0.1 vulnerable to anything critical?"

**Expected behavior (Phase 1):**
1. Intent: `ecosystem=pypi, package=flask, severity=CRITICAL+`
2. SQL finds matching rows in `affected_packages` where `flask` in `pypi` with version `2.0.1` in `vulnerable_versions` range.
3. LLM responds with specific CVEs, what they affect, whether exploits exist, and the recommended upgrade target.

**Expected behavior (Phase 1.5 addition):**
4. Vector search enriches response with crawled advisory prose — remediation details, workaround instructions, context from vendor blog posts.

**Query:** "What vulnerabilities involve authentication bypass in web frameworks?"

**Expected behavior (Phase 1):**
1. Intent: no clean structured filter — `query_type=general_search`.
2. SQL can only do a rough `ILIKE '%authentication bypass%'` on descriptions. Results are limited and noisy.
3. LLM does its best with sparse context.

**Expected behavior (Phase 1.5 addition):**
2. Vector search finds semantically related crawled content even when exact keywords don't match.
3. Much richer, more relevant results.

**Query:** "Any new critical vulnerabilities in the npm ecosystem this week?"

**Expected behavior:**
1. Intent: `ecosystem=npm, severity=CRITICAL, date_range=last 7 days`
2. SQL query with filters — this is a purely structured query, works well in both phases.
3. LLM presents a digest-style summary of each finding.

---

### 6.5 CLI Interface

Phase 1 provides a command-line interface for interacting with the system.

#### 6.5.1 Commands

```bash
# Start the ingestion service (runs continuously with scheduler)
threatwarden ingest start

# Trigger a manual sync for a specific source
threatwarden ingest sync --source nvd
threatwarden ingest sync --all

# Check ingestion status
threatwarden ingest status

# Chat with the query interface (interactive REPL)
threatwarden chat

# One-shot query (non-interactive)
threatwarden query "Is Flask 2.0.1 affected by any critical CVEs?"

# Database stats
threatwarden db stats
```

#### 6.5.2 Implementation

- Built with **Typer** (type-annotated CLI framework).
- Chat mode uses a simple REPL loop with readline support.
- Output formatted with **Rich** (tables, colored severity badges, markdown rendering in terminal).

---

## 7. Tech Stack

### Phase 1

| Component | Technology | Rationale |
|---|---|---|
| Language | Python 3.12+ | Fast development, strong async support, excellent library ecosystem for this domain. |
| Async Runtime | asyncio + httpx | Non-blocking HTTP calls to multiple APIs concurrently. |
| Database | PostgreSQL 16 | Relational storage for structured vulnerability data. |
| DB Driver | asyncpg | High-performance async PostgreSQL driver. Raw SQL, no ORM. |
| LLM (Intent) | gpt-4.1-mini | Lightweight model for parsing user questions into SQL filters. |
| LLM (Synthesis) | Configurable (GPT-5.2, Claude Sonnet, etc.) | Strong instruction following, good at synthesis with citations. |
| Scheduler | asyncio (TaskGroup) | Plain async tasks with sleep intervals. No external dependency needed. |
| CLI | Typer + Rich | Clean CLI with type hints, beautiful terminal output. |
| Config | `os.getenv` + python-dotenv | Simple env var loading from `.env` file. |
| Containerization | Docker + Docker Compose | Postgres + ThreatWarden service in one `docker compose up`. |

### Phase 1.5 additions

| Component | Technology | Rationale |
|---|---|---|
| Vector Extension | pgvector | Adds vector search to existing PostgreSQL — no new service. |
| Embeddings | OpenAI `text-embedding-3-small` | Good quality-to-cost ratio, simple API. Swappable to local model later. |
| LLM (Summarization) | gpt-4.1-mini | Summarizes crawled content before embedding. Same model as intent parsing — cheap and fast. |
| Web Crawling | httpx + Playwright (fallback) | httpx for static pages, Playwright for JS-rendered content. |
| Content Extraction | readability-lxml or similar | Strips boilerplate, extracts article text. |

---

## 8. Project Structure

```
ThreatWarden/
├── .env.example                # Required environment variables template
├── .gitignore
├── docker-compose.yml          # Postgres container
├── pyproject.toml              # Pytest configuration
├── README.md                   # This document
├── requirements.txt            # Python dependencies
├── src/
│   ├── scheduler.py            # Entry point — asyncio scheduler for all ingestors
│   ├── cli/
│   │   ├── main.py             # Typer entry point, composes sub-apps
│   │   ├── common.py           # Shared helpers (DB pool, logging, async decorator)
│   │   ├── ingest.py           # ingest start / sync / status commands
│   │   ├── chat.py             # chat REPL + one-shot query command
│   │   └── db.py               # db stats command
│   ├── db/
│   │   ├── schema.sql          # Authoritative DDL (CREATE TABLE IF NOT EXISTS)
│   │   └── writer.py           # Stateless upsert functions + sync metadata
│   ├── ingestion/
│   │   ├── base.py             # Ingestor ABC, data classes, shared HTTP helpers
│   │   ├── nvd.py              # NVD API v2.0 ingestor
│   │   ├── github.py           # GitHub Advisory REST API ingestor
│   │   ├── exploitdb.py        # Exploit-DB ingestor
│   │   ├── osv.py              # OSV.dev ingestor
│   │   ├── cisa_kev.py         # CISA KEV ingestor (stub)
│   │   └── epss.py             # EPSS ingestor (stub)
│   └── querying/
│       ├── intent_parser.py    # Intent parsing (LLM structured output → SQL filters)
│       ├── retriever.py        # SQL query builder from parsed intent
│       ├── context_assembler.py # Context assembly + ranking + token budget
│       ├── synthesizer.py      # LLM synthesis (grounded + conversational paths)
│       ├── verifier.py         # Self-critique: checks claims against context
│       └── engine.py           # Full query pipeline orchestration
│
│   # Phase 1.5 additions (three independent stages):
│   ├── crawler/                # Stage 1: Web crawling
│   │   ├── crawler.py          # URL fetching + content extraction
│   │   └── targets.py          # Crawl target selection from cve_references
│   ├── summarizer/             # Stage 2: LLM summarization
│   │   └── summarizer.py       # Summarize crawled_content where summary IS NULL
│   └── embeddings/             # Stage 3: Embedding generation
│       └── embedder.py         # Embed summaries, not raw content
│
└── tests/
    ├── test_ingestion/
    │   ├── test_base.py        # Retry logic, shared HTTP helpers
    │   ├── test_nvd.py         # NVD ingestor tests
    │   ├── test_github.py      # GitHub ingestor tests
    │   ├── test_exploitdb.py   # Exploit-DB ingestor tests
    │   └── test_osv.py         # OSV ingestor tests
    └── test_querying/
        ├── test_intent_parser.py
        ├── test_retriever.py
        ├── test_context_assembler.py
        ├── test_synthesizer.py
        ├── test_verifier.py
        └── test_engine.py
```

---

## 9. Configuration

All configuration is managed through environment variables, loaded via `python-dotenv` from a `.env` file for local development.

```bash
# .env.example

# ── Phase 1 ──

# PostgreSQL (asyncpg DSN format)
DB_URL=postgresql://threatwarden:threatwarden@localhost:5432/threatwarden

# OpenAI (used for intent parsing and synthesis)
OPENAI_API_KEY=sk-...
LLM_MODEL=gpt-5.2
INTENT_MODEL=gpt-4.1-mini

# NVD (get free key at https://nvd.nist.gov/developers/request-an-api-key)
NVD_API_KEY=...

# GitHub (PAT with read:packages, read:org scopes)
GITHUB_TOKEN=ghp_...

# Scheduling (interval in seconds)
FAST_INTERVAL=7200      # NVD + GitHub: every 2 hours
DAILY_INTERVAL=86400    # CISA KEV + EPSS + Exploit-DB: daily

# Logging
LOG_LEVEL=INFO

# ── Phase 1.5 (uncomment when enabling crawler + embeddings) ──

# EMBEDDING_MODEL=text-embedding-3-small
# SUMMARIZATION_MODEL=gpt-4.1-mini   # Same as intent model
# CRAWL_INTERVAL=43200     # Crawl cycle: every 12 hours
# CRAWL_RATE_LIMIT=2       # Max requests/sec per domain
```

---

## 10. Deployment (Local Development)

Phase 1 runs entirely locally via Docker Compose for Postgres and the host for the ThreatWarden process.

```yaml
# docker-compose.yml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: threatwarden
      POSTGRES_PASSWORD: threatwarden
      POSTGRES_DB: threatwarden
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

Phase 1 uses the standard `postgres:16` image. For Phase 1.5, we'll swap to `pgvector/pgvector:pg16` to enable the pgvector extension for semantic search.

The ThreatWarden scheduler runs on the host during development:

```bash
cd src && python scheduler.py
```

The `init_schema` function runs on startup and creates all tables if they don't exist.

---

## 11. Data Flow — End to End

### 11.1 Ingestion (write path — Phase 1)

1. Scheduler's asyncio task wakes an ingestor after its sleep interval.
2. **Read phase:** Acquire connection, read high-water mark from `sync_metadata`, release connection.
3. **Fetch phase:** Ingestor calls the external API, paginating through results since the checkpoint. No DB connection held during HTTP calls.
4. **Normalize phase:** `normalize_updates` maps `_normalize` over raw results, producing `NormalizedVulnerability` objects.
5. **Write phase:** Acquire connection, open transaction:
   a. For each normalized record, `save_vulnerability` runs `INSERT ... ON CONFLICT` with COALESCE on the `vulnerabilities` table, then upserts sub-records (`affected_packages`, `exploits`, `cve_references`) via `executemany`.
   b. Update `sync_metadata` with the new high-water mark.
   c. Commit transaction.
6. Log summary: "nvd: sync complete (47 records)".
7. Sleep until next interval.

If any step fails, the exception is caught, logged, and the task sleeps until the next cycle. The transaction rolls back, the high-water mark is not updated, and the next run re-fetches the same window safely.

### 11.2 Enrichment (write path — Phase 1.5)

Three independent stages, each using the database as a work queue:

**Stage 1 — Crawl** (every 12 hours):
1. Query `cve_references` for URLs not yet in `crawled_content` (or stale by content hash).
2. Fetch each URL, extract article text via readability parser.
3. Write `raw_content` to `crawled_content`. Set `summary = NULL` for new/changed rows.
4. Sleep until next interval.

**Stage 2 — Summarize** (every 1 hour):
1. Query `crawled_content` for rows where `summary IS NULL`.
2. For each row, call the summarization LLM (gpt-4.1-mini) to produce a vulnerability-focused summary.
3. Write `summary` + `summarized_at`.
4. Sleep until next interval. No-op if no pending rows.

**Stage 3 — Embed** (every 1 hour):
1. Query `crawled_content` LEFT JOIN `embeddings` for summarized rows with no corresponding embedding.
2. Embed each summary via OpenAI API.
3. Upsert into `embeddings`.
4. Sleep until next interval. No-op if no pending rows.

Each stage fails independently. If OpenAI is down, crawling still runs. If crawling is slow, previously-crawled content still gets summarized and embedded. A crashed process resumes cleanly — the work queue is just a SQL query.

### 11.3 Query (read path — Phase 1)

1. User enters a question via CLI (`threatwarden chat` or `threatwarden query`).
2. Intent parser (LLM call) extracts structured filters from natural language.
3. SQL query builder generates parameterized queries using the extracted filters.
4. Query PostgreSQL: JOIN `vulnerabilities`, `affected_packages`, `exploits`, `cve_references`.
5. Context assembled into structured text blocks, truncated to token budget.
6. LLM synthesis call with system prompt + context + user question.
7. **Verification:** Lightweight LLM call checks each claim in the response against the assembled context. Unsupported claims are flagged; omissions are appended.
8. Final response streamed to terminal with Rich formatting (colored severity, clickable links).

### 11.4 Query (read path — Phase 1.5 additions)

Steps 1-4 remain the same. After the SQL path:

5. Semantic search via pgvector: embed `raw_search_query`, cosine similarity against `embeddings`, filtered by SQL WHERE/JOIN.
6. Merge SQL results + vector results, deduplicate by `cve_id`, rank by severity signals.
7. Context assembly and LLM synthesis as before, but with richer crawled prose in the context.

---

## 12. Success Metrics

### Phase 1

| Metric | Target |
|---|---|
| Sources ingesting without error | >= 4 of 6 sources running on schedule |
| CVE coverage | >= 50,000 CVEs in database after initial sync |
| Ingestion freshness | New CVEs appear within 4 hours of NVD publication |
| Query response time | < 10 seconds end-to-end (including verification) |
| Answer grounding | 100% of cited CVE IDs exist in the database (enforced by verification) |
| Verification catch rate | 0 unsupported claims reach the user in verified responses |
| Basic accuracy | Correct package/version matching for top 2 ecosystems (pypi, npm) |

### Phase 1.5

| Metric | Target |
|---|---|
| Crawled coverage | >= 50% of reference URLs in `cve_references` successfully crawled |
| Summarization rate | >= 90% of crawled pages produce a non-trivial summary |
| Embedding coverage | All summarized CVEs have corresponding embeddings |
| Semantic query improvement | Queries that returned no/poor results via SQL alone return relevant results via vector search |

---

## 13. Risks & Mitigations

| Risk | Phase | Impact | Mitigation |
|---|---|---|---|
| NVD API rate limiting / downtime | 1 | Stale data | Use API key (higher limits), implement backoff, fall back to GitHub Advisory and OSV data. |
| LLM hallucination in synthesis | 1 | Users act on fabricated info | Verification step catches unsupported claims before user sees them. All cited CVE IDs validated against context. |
| Version range matching is complex | 1 | False positives/negatives in package matching | Use established semver parsing libraries (`packaging` for pypi, `semver` for npm). OSV.dev provides machine-readable ranges as supplement. |
| Initial NVD sync is massive (~250K CVEs) | 1 | Long first-run, memory pressure | Stream processing — don't load all into memory. Process in pages of 2,000. Use NVD's bulk download for initial seed. |
| Verification adds latency | 1 | Slower query response | Verification uses the lightweight model (gpt-4.1-mini). Input is small (context + response). Expect <1s overhead. Can be made optional via flag. |
| OpenAI API cost at scale | 1.5 | High summarization + embedding cost | Summarize-then-embed reduces vector count vs. raw chunking. Use gpt-4.1-mini for summaries (cheap). Phase 1 has no embedding cost — only intent + synthesis + verification. |
| Crawled content quality varies | 1.5 | Poor summaries, noisy retrieval | LLM summarization filters noise before embedding. Domain allowlist as additional guard. |
| Scope creep into SAST / code scanning | 1 | Phase 1 never ships | Hard boundary: Phase 1 is data pipeline + query only. No codebase scanning. |
| Phase 1.5 before Phase 1 is solid | 1.5 | Premature complexity | Phase 1 must be feature-complete and stable before starting crawler/embeddings work. |

---

## 14. Open Questions

### Phase 1

1. **Semver matching fidelity?** GitHub Advisory provides version ranges, but matching a user-supplied version against those ranges requires per-ecosystem logic (pypi uses PEP 440, npm uses node-semver, Go uses its own scheme). OSV.dev's standardized format may help. Start with pypi + npm; expand ecosystem coverage iteratively.

2. **Initial NVD sync batching?** The full NVD sync (~250K CVEs) accumulates all records in memory before writing. May need batched writes (process N records at a time) if memory becomes an issue on first run.

3. **SQL query generation robustness?** The intent parser must produce valid SQL filters. Need guardrails against malformed output (validate extracted fields before building queries, use parameterized queries exclusively).

4. **Verification granularity?** The self-critique step could operate at different levels — per-response (coarse, cheap) or per-claim (fine, more LLM tokens). Start with per-response and evaluate whether per-claim granularity is worth the additional cost.

### Phase 1.5

5. **Local embedding model vs. OpenAI?** Using OpenAI is simpler to start, but for a security tool, sending vulnerability context to an external API may be a concern. Evaluate `nomic-embed-text` via Ollama as an alternative.

6. **Crawl scope and domain allowlist?** Which domains are worth crawling? Vendor advisories are high-signal, but random blog posts may introduce noise. Need a curated domain allowlist or quality heuristic.

7. **Summarization quality threshold?** When the LLM summary is too short or vague (e.g., page had no vulnerability-relevant content), should we still embed it? Need a minimum-quality gate before embedding.

### General

8. **Hosting for Phase 2?** Phase 1 is local-only. If this grows, evaluate Railway, Fly.io, or a small VPS for running the ingestion service 24/7.



---

## 15. Future Work

### Phase 1.5 — Crawler, Summarization & Semantic Search

Out of scope for Phase 1, but designed and ready to implement once Phase 1 is stable:

- **Three-stage enrichment pipeline**, each stage independent with the database as the work queue:
  1. **Crawl:** Fetch advisory content from reference URLs in `cve_references`. Extract article text, store raw content in `crawled_content`.
  2. **Summarize:** LLM-summarize each crawled page into a vulnerability-focused summary (exploitation, remediation, affected versions). Runs independently of crawling — processes rows where `summary IS NULL`.
  3. **Embed:** Embed summaries (not raw content) via OpenAI, store in `embeddings` table with pgvector. Runs independently of summarization — processes summarized rows with no corresponding embedding.
- **Semantic query path:** Add vector similarity search alongside existing SQL path. Merge and rank results.
- **Trigger:** Phase 1 is feature-complete, ingestion is running reliably, SQL-based queries with verification work end-to-end.

### Phase 2 — Codebase-Aware Intelligence

Phase 2 shifts ThreatWarden from "ask about vulnerabilities" to "tell me what matters for my code." The key differentiator from existing SCA tools (OWASP Dependency-Track, Google OSV-Scanner, Snyk) is that ThreatWarden already has a rich, continuously-updated corpus with exploit maturity signals and (from Phase 1.5) crawled advisory prose. Phase 2 connects that corpus to a specific codebase, and its alerts include LLM-synthesized context rather than raw CVE IDs.

#### 2a — Dependency Scanning & Project Registration

- **Manifest parsing:** Parse `requirements.txt`/`pyproject.toml` (pypi), `package.json`/`package-lock.json` (npm), `go.mod` (Go), `Cargo.toml` (Rust) to extract dependency names and pinned versions.
- **Version matching:** Match extracted versions against `affected_packages` version ranges. Leverage OSV.dev's machine-readable ranges (already ingested in Phase 1) for reliable cross-ecosystem matching.
- **Project registration:** Store scanned projects in a `projects` table with their dependency snapshots. A project is a directory path + a name + a list of `(ecosystem, package, version)` tuples.
- **CLI integration:** `threatwarden scan /path/to/project` produces an instant vulnerability report for the project's dependencies, using the same LLM synthesis + verification pipeline from Phase 1.
- **What existing tools do better:** OSV-Scanner and Dependency-Track have mature manifest parsers for dozens of ecosystems. ThreatWarden shouldn't reimplement all of them — consider wrapping OSV-Scanner's output as an input source rather than parsing every lockfile format from scratch.
- **What ThreatWarden adds:** The scan result isn't a flat list of CVE IDs. It's a prioritized, LLM-synthesized briefing: "Your Flask 2.0.1 has 3 critical vulnerabilities. CVE-2025-XXXX is actively exploited per CISA and has a public PoC. Upgrade to 2.3.1. CVE-2025-YYYY is lower risk — EPSS 0.02, no known exploit."

#### 2b — Continuous Monitoring & Alerting

- **Watch mode:** After registering a project, ThreatWarden monitors the ingestion pipeline for new CVEs that match the project's dependencies. When a new match appears, it generates a notification.
- **Contextual alerts:** Unlike Dependency-Track or Snyk which send "CVE-2025-XXXX affects flask," ThreatWarden's alerts include the LLM-synthesized summary from Phase 1's query engine — what the vulnerability is, exploit maturity, remediation steps, and a severity assessment in context of the project.
- **Notification channels:** Slack, Discord, email (via webhook integrations). Alerts are formatted with severity badges and actionable next steps.
- **Alert fatigue mitigation:** Not every new CVE warrants a notification. Filter by: severity threshold (configurable), exploit maturity (KEV or EPSS > threshold), and whether the project's pinned version actually falls in the vulnerable range (not just "this package has a CVE somewhere").

#### 2c — Web UI & API Server

- **API:** FastAPI-based HTTP API exposing the same query engine as the CLI. Endpoints for querying, scanning, project management, and ingestion status.
- **Dashboard:** Lightweight web UI showing:
  - Per-project vulnerability summary (critical/high/medium/low counts, trending).
  - Ingestion pipeline health (last sync times, record counts, errors).
  - Recent alerts timeline.
  - Interactive query interface (same LLM synthesis as CLI, but in the browser).
- **Why not earlier:** The CLI is sufficient for Phase 1. A web UI adds frontend complexity (React/Vue/Svelte, auth, deployment) that shouldn't block the core pipeline from shipping.

#### 2d — Threat Context Enrichment (Stretch)

- **ATT&CK mapping:** Link CVEs to MITRE ATT&CK techniques using CWE→CAPEC→ATT&CK relationships (the graph structure that BRON models). This enriches answers with tactical context: "This vulnerability maps to T1190 (Exploit Public-Facing Application) and is commonly used in initial access campaigns."
- **Deep analysis mode:** For specific CVE deep dives, combine the pre-ingested corpus (Phase 1) with ProveRAG-style query-time web retrieval — fetch and summarize additional sources live to provide maximum depth. This is the best of both architectures: persistent corpus for breadth, live retrieval for depth.
- **SAST integration (long-term):** Wrap Semgrep or CodeQL for insecure code pattern detection beyond dependency vulnerabilities. This is well-served by existing tools and should only be pursued if ThreatWarden's conversational interface adds meaningful value over running Semgrep directly.
