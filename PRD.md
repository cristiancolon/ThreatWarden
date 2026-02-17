# Sentinel — Product Requirements Document

## Phase 1: Vulnerability Intelligence Pipeline & RAG Interface

**Version:** 0.1.0
**Last Updated:** February 17, 2026
**Status:** Draft

---

## 1. Overview

Sentinel is a continuously-running vulnerability intelligence system that aggregates exploit and CVE data from authoritative sources, stores it in both a relational database and a vector store, and exposes that knowledge through a conversational LLM interface (RAG). The goal is to let a developer ask natural-language questions about vulnerabilities relevant to their stack and get grounded, cited, prioritized answers.

Phase 1 covers the ingestion pipeline, data storage, and RAG query interface. It does **not** cover codebase scanning, continuous project monitoring, or static analysis — those are Phase 2 concerns.

---

## 2. Problem Statement

Security vulnerability data is fragmented across dozens of sources (NVD, GitHub Advisories, CISA KEV, Exploit-DB, EPSS feeds). A developer who wants to understand their exposure must manually cross-reference CVE databases, check exploit maturity, parse CVSS scores, and read advisory prose. This is tedious, error-prone, and rarely done proactively.

Sentinel solves this by:

1. Continuously aggregating and normalizing vulnerability data from structured feeds.
2. Enriching that data with exploit maturity signals (PoC availability, KEV inclusion, EPSS probability).
3. Making the full corpus queryable via natural language through an LLM grounded in the collected data.

---

## 3. Goals & Non-Goals

### Goals

- Ingest CVE/advisory data from at least four authoritative sources on an automated schedule.
- Store structured vulnerability records in PostgreSQL with proper relational modeling.
- Store advisory text, exploit descriptions, and enrichment prose as vector embeddings for semantic retrieval.
- Provide a conversational interface where a user can ask questions about vulnerabilities, packages, or ecosystems and receive grounded answers with citations.
- Deduplicate and update records as sources publish revisions.
- Track exploit maturity: flag when a CVE has a known public exploit, a Metasploit module, or appears on CISA's Known Exploited Vulnerabilities catalog.

### Non-Goals (Phase 1)

- Codebase or dependency scanning (Phase 2).
- Static analysis / insecure code pattern detection (Phase 2+).
- Continuous project monitoring and alerting (Phase 2).
- Web UI (CLI and programmatic access only in Phase 1).
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
┌────────────────────────────────────────────────────-───┐
│                   Ingestion Service                    │
│                                                        │
│  ┌───────────┐ ┌──────────┐ ┌────────┐ ┌──────────┐    │
│  │  NVD API  │ │ GitHub   │ │ CISA   │ │ EPSS     │    │
│  │  Fetcher  │ │ Advisory │ │ KEV    │ │ Fetcher  │    │
│  │           │ │ Fetcher  │ │ Fetcher│ │          │    │
│  └─────┬─────┘ └────┬─────┘ └───┬────┘ └────┬─────┘    │ 
│        │             │           │            │        │
│        └──────┬──────┴─────┬─────┴────────────┘        │
│               │            │                           │
│         ┌─────▼─────┐ ┌───▼────┐                       │
│         │ Normalizer│ │ Dedup  │                       │
│         └─────┬─────┘ └───┬────┘                       │
│               └─────┬─────┘                            │
└─────────────────────┼──────────────────────────────────┘
                      │
          ┌───────────┼───────────┐
          │           │           │
    ┌─────▼─────┐ ┌───▼────┐ ┌───▼──────┐
    │ PostgreSQL │ │ Vector │ │ Chunker  │
    │  (struct)  │ │ Store  │ │ +Embedder│
    └─────┬─────┘ └───┬────┘ └──────────┘
          │           │
          └─────┬─────┘
                │
          ┌─────▼─────┐
          │  RAG      │
          │  Query    │
          │  Engine   │
          └─────┬─────┘
                │
          ┌─────▼─────┐
          │  CLI /    │
          │  Chat     │
          │  Interface│
          └───────────┘
```

---

## 6. Component Specifications

### 6.1 Ingestion Service

The ingestion service is a long-running process (or scheduled job) that periodically fetches vulnerability data from external sources, normalizes it, and writes it to both PostgreSQL and the vector store.

#### 6.1.1 Data Sources

Each source is implemented as an independent fetcher module behind a common interface. This makes it straightforward to add new sources later.

| Source | Method | Frequency | Data Provided | Priority |
|---|---|---|---|---|
| **NVD (National Vulnerability Database)** | REST API v2.0 (`api.nvd.nist.gov`) | Every 2 hours | CVE records, CVSS v3.1 scores, CPE match strings, descriptions, references | P0 — primary CVE source |
| **GitHub Security Advisories** | GraphQL API (`api.github.com/graphql`) | Every 2 hours | Package-level vulnerability mappings (ecosystem, package name, vulnerable version ranges, patched versions) | P0 — best for dependency-level matching |
| **CISA KEV** | Static JSON download (`cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`) | Daily | Confirmed actively-exploited CVE IDs, due dates, required actions | P0 — critical severity signal |
| **EPSS (Exploit Prediction Scoring System)** | CSV download (`epss.cyentia.com`) | Daily | Probability score (0–1) that a CVE will be exploited in the next 30 days, percentile | P1 — prioritization signal |
| **Exploit-DB** | Git mirror clone + CSV index (`gitlab.com/exploit-database/exploitdb`) | Daily | Proof-of-concept exploit code, metadata, linked CVEs | P1 — exploit maturity signal |

#### 6.1.2 Fetcher Interface

Every fetcher module must implement the following contract:

```python
class BaseFetcher(ABC):
    @abstractmethod
    async def fetch_updates(self, since: datetime | None) -> list[RawVulnerability]:
        """
        Fetch new or updated vulnerability records since the given timestamp.
        If `since` is None, perform a full initial sync.
        Returns a list of normalized intermediate records.
        """
        ...

    @abstractmethod
    def source_name(self) -> str:
        """Return the canonical name of this source (e.g., 'nvd', 'github_advisory')."""
        ...
```

Each fetcher handles its own pagination, rate limiting, and retry logic. The service orchestrates calling them on schedule.

#### 6.1.3 Normalizer

Raw records from different sources are mapped into a common `NormalizedVulnerability` structure before being written to storage. The normalizer:

- Resolves the canonical CVE ID as the primary key.
- Merges data from multiple sources for the same CVE (e.g., NVD provides CVSS, GitHub provides package-level mappings, EPSS provides probability scores).
- Handles conflict resolution: NVD is authoritative for CVSS scores; GitHub is authoritative for package version ranges; CISA KEV is authoritative for active exploitation status.

#### 6.1.4 Deduplication

- Primary dedup key: `cve_id`.
- On conflict, update fields that have changed and bump `updated_at`.
- Track `source` on each sub-record (affected packages, exploits) to avoid clobbering source-specific data.
- Maintain a `sync_metadata` table to track the high-water mark (last successful fetch timestamp) per source.

#### 6.1.5 Scheduling

- Use **APScheduler** (AsyncIOScheduler) running within the service process.
- Configurable intervals per source via environment variables.
- Default schedule:
  - NVD, GitHub Advisory: every 2 hours.
  - CISA KEV, EPSS, Exploit-DB: once daily at 06:00 UTC.
- On first run, perform a full historical sync (NVD allows bulk download; GitHub Advisory supports `UPDATED_SINCE` cursor).

#### 6.1.6 Rate Limiting & Resilience

- NVD: honor 50 requests/30s with API key (5 requests/30s without). Obtain a free API key.
- GitHub: 5,000 requests/hour with PAT. Use cursor-based pagination.
- Implement exponential backoff with jitter on transient failures (HTTP 429, 5xx).
- Log all fetch errors; do not let a single source failure block other sources.

---

### 6.2 Data Storage — PostgreSQL

#### 6.2.1 Schema

```sql
-- Tracks sync state per ingestion source
CREATE TABLE sync_metadata (
    source_name TEXT PRIMARY KEY,
    last_successful_sync TIMESTAMP WITH TIME ZONE,
    last_cursor TEXT,  -- source-specific pagination cursor
    records_synced INTEGER DEFAULT 0,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Core vulnerability record (one per CVE)
CREATE TABLE vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    cvss_score FLOAT,
    cvss_vector TEXT,
    cvss_version TEXT,         -- '3.1', '4.0', etc.
    epss_score FLOAT,          -- 0.0 to 1.0
    epss_percentile FLOAT,     -- 0.0 to 1.0
    cisa_kev BOOLEAN DEFAULT FALSE,
    cisa_kev_due_date DATE,
    severity TEXT,              -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE'
    published_at TIMESTAMP WITH TIME ZONE,
    modified_at TIMESTAMP WITH TIME ZONE,
    created_in_db TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_in_db TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    raw_sources TEXT[]          -- ['nvd', 'github_advisory', 'cisa_kev']
);

-- Affected packages, linked to CVE (source: primarily GitHub Advisory)
CREATE TABLE affected_packages (
    id SERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,        -- 'npm', 'pypi', 'go', 'maven', 'cargo', 'nuget', etc.
    package_name TEXT NOT NULL,
    vulnerable_versions TEXT,       -- semver range string, e.g., '>=1.0.0 <1.2.3'
    patched_version TEXT,
    source TEXT NOT NULL,           -- which feed provided this mapping
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE (cve_id, ecosystem, package_name, source)
);

-- Known exploits and PoC references
CREATE TABLE exploits (
    id SERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    source TEXT NOT NULL,           -- 'exploit-db', 'github', 'metasploit', 'nuclei'
    source_id TEXT,                 -- ID within that source
    url TEXT,
    description TEXT,
    discovered_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    UNIQUE (cve_id, source, source_id)
);

-- CVE references (links to advisories, patches, discussions)
CREATE TABLE cve_references (
    id SERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities(cve_id) ON DELETE CASCADE,
    url TEXT NOT NULL,
    ref_type TEXT,                  -- 'advisory', 'patch', 'exploit', 'article'
    source TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for common query patterns
CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX idx_vuln_published ON vulnerabilities(published_at DESC);
CREATE INDEX idx_vuln_epss ON vulnerabilities(epss_score DESC NULLS LAST);
CREATE INDEX idx_vuln_kev ON vulnerabilities(cisa_kev) WHERE cisa_kev = TRUE;
CREATE INDEX idx_affected_pkg_ecosystem ON affected_packages(ecosystem, package_name);
CREATE INDEX idx_affected_pkg_cve ON affected_packages(cve_id);
CREATE INDEX idx_exploits_cve ON exploits(cve_id);
```

#### 6.2.2 Key Design Decisions

- **CVE as spine:** Every record ultimately links back to a `cve_id`. This is the universal join key across all sources.
- **Multi-source merging:** The `raw_sources` array on `vulnerabilities` tracks which feeds contributed data. Sub-tables (`affected_packages`, `exploits`) track source per row with unique constraints to prevent duplicates.
- **Severity as computed field:** Derived from CVSS score at write time (`CRITICAL` >= 9.0, `HIGH` >= 7.0, `MEDIUM` >= 4.0, `LOW` > 0, `NONE` = 0).
- **Soft deletion not needed:** CVEs are never deleted, only updated. If NVD rejects a CVE, mark it with a `REJECTED` status rather than removing.

---

### 6.3 Data Storage — Vector Store

#### 6.3.1 Technology Choice

**Qdrant** (self-hosted via Docker or Qdrant Cloud free tier).

Rationale:
- Production-grade filtering support (critical for narrowing by ecosystem, severity, etc. before semantic search).
- REST and gRPC APIs with a good Python client.
- Simple single-binary Docker deployment.
- Better suited for production path than Chroma (which is designed more for prototyping).

#### 6.3.2 What Gets Embedded

Not every database field needs to live in the vector store. Only text that benefits from semantic retrieval is embedded:

| Content Type | Source | Chunking Strategy |
|---|---|---|
| CVE description + extended advisory text | NVD, GitHub Advisory | One chunk per CVE. If description > 1000 tokens, split at paragraph boundaries. |
| Exploit-DB PoC descriptions and READMEs | Exploit-DB git mirror | One chunk per exploit entry. Strip code blocks > 50 lines (keep first/last 5 lines with `[truncated]`). |
| CVE reference articles (future enrichment) | Web crawl (Phase 1 stretch) | Paragraph-level chunking with overlap. |

#### 6.3.3 Embedding Model

**OpenAI `text-embedding-3-small`** (1536 dimensions).

Rationale: good quality-to-cost ratio, well-documented, trivial to call. Can swap to a local model (e.g., `nomic-embed-text` via Ollama) later if cost becomes a concern.

#### 6.3.4 Metadata Payload

Every vector point stores the following metadata alongside the embedding, enabling filtered search:

```json
{
  "cve_id": "CVE-2025-1234",
  "chunk_type": "cve_description",
  "ecosystem": ["npm", "pypi"],
  "severity": "CRITICAL",
  "cvss_score": 9.8,
  "epss_score": 0.87,
  "cisa_kev": true,
  "has_exploit": true,
  "published_at": "2025-11-01T00:00:00Z",
  "source": "nvd"
}
```

#### 6.3.5 Collection Configuration

- **Collection name:** `sentinel_vulns`
- **Distance metric:** Cosine
- **Vector size:** 1536 (matching embedding model output)
- **Point ID:** Deterministic hash of `(cve_id, chunk_type, chunk_index)` to allow idempotent upserts.

#### 6.3.6 Sync Strategy

When the ingestion service writes or updates a vulnerability in PostgreSQL, it also:

1. Re-generates the text blob for that CVE (description + advisory + exploit info).
2. Re-chunks if necessary.
3. Embeds the chunk(s).
4. Upserts into Qdrant using the deterministic point ID.

This keeps the vector store consistent with the relational store without requiring a separate sync job.

---

### 6.4 RAG Query Engine

#### 6.4.1 Query Flow

```
User Question
     │
     ▼
┌──────────────────┐
│  Intent Parser   │  ← LLM call to extract structured filters from natural language
│                  │     (ecosystem, package names, severity, date range, CVE IDs)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Structured      │  ← Direct SQL query against PostgreSQL using extracted filters
│  DB Lookup       │     Returns matching CVE records with full metadata
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Vector Search   │  ← Semantic search against Qdrant, filtered by extracted metadata
│  (contextual)    │     Retrieves relevant advisory text, exploit descriptions
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Context         │  ← Merges structured DB results + vector search results
│  Assembly        │     Ranks and truncates to fit context window
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  LLM Synthesis   │  ← Generates natural-language answer grounded in retrieved context
│                  │     Includes citations (CVE IDs, source URLs)
└──────────────────┘
```

#### 6.4.2 Intent Parsing

Before searching, the user's question is passed through an LLM call (lightweight, fast model — e.g., `gpt-4o-mini`) with a structured output schema to extract:

```python
class QueryIntent(BaseModel):
    ecosystems: list[str] | None        # e.g., ['pypi', 'npm']
    package_names: list[str] | None     # e.g., ['flask', 'requests']
    cve_ids: list[str] | None           # e.g., ['CVE-2025-1234']
    severity_filter: str | None         # e.g., 'CRITICAL', 'HIGH+'
    date_range: str | None              # e.g., 'last 30 days'
    query_type: str                     # 'specific_cve', 'package_check', 'general_search'
    raw_search_query: str               # cleaned/rephrased query for vector search
```

This dual-path approach (structured SQL + semantic vector search) avoids the common RAG pitfall of relying purely on embedding similarity for data that has strong structured attributes.

#### 6.4.3 Retrieval Strategy

1. **Structured path (SQL):** If the intent parser extracts specific packages, CVE IDs, or ecosystems, query PostgreSQL directly. This gives exact, reliable results for known-item queries.

2. **Semantic path (Vector):** Run a filtered similarity search against Qdrant using:
   - The `raw_search_query` from intent parsing as the embedding input.
   - Metadata filters derived from the parsed intent (ecosystem, severity, date range).
   - Top-k = 10 results.

3. **Merge:** Combine both result sets, deduplicate by `cve_id`, rank by relevance (vector score) weighted by severity signals (EPSS, KEV, exploit availability).

#### 6.4.4 Context Assembly

- Format each retrieved CVE as a structured text block:

```
[CVE-2025-1234] (CRITICAL | CVSS 9.8 | EPSS 0.87 | KEV: Yes | Exploit: Yes)
Affects: flask (pypi) versions >=2.0.0 <2.3.1 — patched in 2.3.1
Description: <advisory text from vector store>
Sources: https://nvd.nist.gov/vuln/detail/CVE-2025-1234
```

- Total context budget: ~6,000 tokens of retrieved content (leaving room for system prompt + user question + response).
- If more than budget, prioritize by: KEV status > has-exploit > EPSS score > CVSS score > recency.

#### 6.4.5 LLM Synthesis

- **Model:** GPT-4o (or Claude 3.5 Sonnet — configurable).
- **System prompt** instructs the model to:
  - Only answer based on the provided context.
  - Always cite CVE IDs.
  - Clearly state when no relevant vulnerabilities were found.
  - Recommend specific actions (upgrade to version X, apply workaround Y).
  - Flag exploit maturity clearly ("a public PoC exists," "actively exploited per CISA").
- **Temperature:** 0.1 (factual, low creativity).

#### 6.4.6 Example Interactions

**Query:** "Is Flask 2.0.1 vulnerable to anything critical?"

**Expected behavior:**
1. Intent: `ecosystem=pypi, package=flask, severity=CRITICAL+`
2. SQL finds matching rows in `affected_packages` where `flask` in `pypi` with version `2.0.1` falling in `vulnerable_versions` range.
3. Vector search enriches with advisory prose for matching CVEs.
4. LLM responds with specific CVEs, what they affect, whether exploits exist, and the recommended upgrade target.

**Query:** "What's CVE-2025-29927?"

**Expected behavior:**
1. Intent: `cve_id=CVE-2025-29927, query_type=specific_cve`
2. SQL fetches the full record directly.
3. Vector search pulls advisory text and any exploit description.
4. LLM summarizes the vulnerability, affected packages, severity, exploit status, and remediation.

**Query:** "Any new critical vulnerabilities in the npm ecosystem this week?"

**Expected behavior:**
1. Intent: `ecosystem=npm, severity=CRITICAL, date_range=last 7 days`
2. SQL query with filters.
3. Vector search for recent npm advisories.
4. LLM presents a digest-style summary of each finding.

---

### 6.5 CLI Interface

Phase 1 provides a command-line interface for interacting with the system.

#### 6.5.1 Commands

```bash
# Start the ingestion service (runs continuously with scheduler)
sentinel ingest start

# Trigger a manual sync for a specific source
sentinel ingest sync --source nvd
sentinel ingest sync --all

# Check ingestion status
sentinel ingest status

# Chat with the RAG interface (interactive REPL)
sentinel chat

# One-shot query (non-interactive)
sentinel query "Is Flask 2.0.1 affected by any critical CVEs?"

# Database stats
sentinel db stats
```

#### 6.5.2 Implementation

- Built with **Typer** (type-annotated CLI framework).
- Chat mode uses a simple REPL loop with readline support.
- Output formatted with **Rich** (tables, colored severity badges, markdown rendering in terminal).

---

## 7. Tech Stack

| Component | Technology | Rationale |
|---|---|---|
| Language | Python 3.12+ | Fast development, strong async support, excellent library ecosystem for this domain. |
| Async Runtime | asyncio + httpx | Non-blocking HTTP calls to multiple APIs concurrently. |
| Database | PostgreSQL 16 | Robust relational storage, good JSON support, reliable. |
| DB Driver | asyncpg | High-performance async PostgreSQL driver. |
| Migrations | Alembic | Industry-standard schema migrations for SQLAlchemy. |
| ORM | SQLAlchemy 2.0 (async) | Type-safe query building, async session support. |
| Vector Store | Qdrant | Filtered vector search, simple deployment, good Python client. |
| Embeddings | OpenAI `text-embedding-3-small` | Good quality-to-cost ratio, simple API. |
| LLM | OpenAI GPT-4o (configurable) | Strong instruction following, good at synthesis with citations. |
| LLM Framework | LangChain or raw OpenAI SDK | LangChain only if its abstractions add clear value; otherwise, raw SDK to avoid unnecessary complexity. |
| Scheduler | APScheduler (AsyncIOScheduler) | In-process scheduling, no external dependency. |
| CLI | Typer + Rich | Clean CLI with type hints, beautiful terminal output. |
| Config | Pydantic Settings | Typed config from env vars / `.env` file. |
| Containerization | Docker + Docker Compose | Postgres + Qdrant + Sentinel service in one `docker compose up`. |

---

## 8. Project Structure

```
sentinel/
├── pyproject.toml              # Project metadata, dependencies (using uv or poetry)
├── .env.example                # Required environment variables template
├── docker-compose.yml          # Postgres + Qdrant + Sentinel
├── alembic/                    # Database migrations
│   ├── alembic.ini
│   └── versions/
├── src/
│   └── sentinel/
│       ├── __init__.py
│       ├── main.py             # Entry point, CLI definition
│       ├── config.py           # Pydantic Settings configuration
│       ├── db/
│       │   ├── __init__.py
│       │   ├── engine.py       # Async SQLAlchemy engine + session
│       │   ├── models.py       # SQLAlchemy ORM models
│       │   └── queries.py      # Common query functions
│       ├── ingestion/
│       │   ├── __init__.py
│       │   ├── base.py         # BaseFetcher ABC
│       │   ├── nvd.py          # NVD API fetcher
│       │   ├── github.py       # GitHub Advisory fetcher
│       │   ├── cisa_kev.py     # CISA KEV fetcher
│       │   ├── epss.py         # EPSS score fetcher
│       │   ├── exploitdb.py    # Exploit-DB fetcher
│       │   ├── normalizer.py   # Raw → NormalizedVulnerability mapping
│       │   └── scheduler.py    # APScheduler setup + job definitions
│       ├── vectorstore/
│       │   ├── __init__.py
│       │   ├── client.py       # Qdrant client wrapper
│       │   ├── embedder.py     # Embedding generation (OpenAI)
│       │   └── chunker.py      # Text chunking logic
│       ├── rag/
│       │   ├── __init__.py
│       │   ├── intent.py       # Query intent parsing (LLM structured output)
│       │   ├── retriever.py    # Dual-path retrieval (SQL + vector)
│       │   ├── context.py      # Context assembly + ranking
│       │   └── engine.py       # Full RAG pipeline orchestration
│       └── cli/
│           ├── __init__.py
│           ├── ingest.py       # `sentinel ingest` commands
│           ├── chat.py         # `sentinel chat` / `sentinel query` commands
│           └── db.py           # `sentinel db` commands
└── tests/
    ├── conftest.py
    ├── test_ingestion/
    ├── test_vectorstore/
    └── test_rag/
```

---

## 9. Configuration

All configuration is managed through environment variables, loaded via Pydantic Settings with an `.env` file for local development.

```bash
# .env.example

# PostgreSQL
SENTINEL_DB_URL=postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel

# Qdrant
SENTINEL_QDRANT_URL=http://localhost:6333
SENTINEL_QDRANT_COLLECTION=sentinel_vulns

# OpenAI
SENTINEL_OPENAI_API_KEY=sk-...
SENTINEL_EMBEDDING_MODEL=text-embedding-3-small
SENTINEL_LLM_MODEL=gpt-4o

# NVD (get free key at https://nvd.nist.gov/developers/request-an-api-key)
SENTINEL_NVD_API_KEY=...

# GitHub (PAT with read:packages, read:org scopes)
SENTINEL_GITHUB_TOKEN=ghp_...

# Scheduling (cron expressions or interval seconds)
SENTINEL_NVD_INTERVAL_SECONDS=7200
SENTINEL_GITHUB_INTERVAL_SECONDS=7200
SENTINEL_DAILY_SYNC_HOUR=6

# Logging
SENTINEL_LOG_LEVEL=INFO
```

---

## 10. Deployment (Local Development)

Phase 1 runs entirely locally via Docker Compose.

```yaml
# docker-compose.yml
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER: sentinel
      POSTGRES_PASSWORD: sentinel
      POSTGRES_DB: sentinel
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  qdrant:
    image: qdrant/qdrant:latest
    ports:
      - "6333:6333"
      - "6334:6334"
    volumes:
      - qdrant_data:/qdrant/storage

volumes:
  pgdata:
  qdrant_data:
```

The Sentinel application itself runs on the host during development (`sentinel ingest start` in one terminal, `sentinel chat` in another). It connects to the Dockerized Postgres and Qdrant.

---

## 11. Data Flow — End to End

### 11.1 Ingestion (write path)

1. Scheduler triggers a fetcher (e.g., NVD) based on its configured interval.
2. Fetcher calls the external API, paginating through results since the last sync checkpoint.
3. Raw results are passed to the normalizer, producing `NormalizedVulnerability` objects.
4. For each normalized record:
   a. **Upsert to PostgreSQL:** Insert or update the `vulnerabilities` row. Insert/update related `affected_packages` and `exploits` rows.
   b. **Generate embeddings:** Concatenate the description + advisory text. Chunk if over token limit. Call embedding API.
   c. **Upsert to Qdrant:** Write vector point(s) with metadata payload using deterministic IDs.
5. Update `sync_metadata` with the new high-water mark for this source.
6. Log summary: "NVD sync complete: 47 new, 12 updated, 0 errors."

### 11.2 Query (read path)

1. User enters a question via CLI (`sentinel chat` or `sentinel query`).
2. Intent parser (LLM call) extracts structured filters + cleaned search query.
3. If specific packages/CVEs identified → SQL query to PostgreSQL.
4. Semantic search to Qdrant using cleaned query + metadata filters.
5. Results merged, deduplicated, ranked by severity signals.
6. Context assembled into structured text blocks, truncated to token budget.
7. LLM synthesis call with system prompt + context + user question.
8. Response streamed to terminal with Rich formatting (colored severity, clickable links).

---

## 12. Success Metrics

Phase 1 is considered successful when:

| Metric | Target |
|---|---|
| Sources ingesting without error | >= 4 of 5 sources running on schedule |
| CVE coverage | >= 50,000 CVEs in database after initial sync |
| Ingestion freshness | New CVEs appear within 4 hours of NVD publication |
| Query response time | < 10 seconds end-to-end for a RAG query |
| Answer grounding | 100% of cited CVE IDs exist in the database |
| Basic accuracy | Correct package/version matching for top 2 ecosystems (pypi, npm) |

---

## 13. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| NVD API rate limiting / downtime | Stale data | Use API key (higher limits), implement backoff, fall back to GitHub Advisory data. |
| OpenAI API cost at scale | High embedding/query cost | Use `text-embedding-3-small` (cheapest), cache embeddings, batch embed calls. Monitor costs. |
| Version range matching is complex | False positives/negatives in package matching | Use established semver parsing libraries (`packaging` for pypi, `semver` for npm). Don't roll your own. |
| Initial NVD sync is massive (~250K CVEs) | Long first-run, memory pressure | Stream processing — don't load all into memory. Process in pages of 2,000. Use NVD's bulk download for initial seed. |
| Scope creep into SAST / code scanning | Phase 1 never ships | Hard boundary: Phase 1 is data pipeline + RAG only. No codebase scanning. |

---

## 14. Open Questions

1. **Local embedding model vs. OpenAI?** Using OpenAI is simpler to start, but for a security tool, sending vulnerability context to an external API may be a concern. Evaluate `nomic-embed-text` via Ollama as an alternative after MVP.

2. **LangChain or raw SDK?** LangChain adds a lot of abstraction. For Phase 1, the RAG pipeline is simple enough that raw OpenAI SDK + manual orchestration may be cleaner. Decide during implementation.

3. **Semver matching fidelity?** GitHub Advisory provides version ranges, but matching a user-supplied version against those ranges requires per-ecosystem logic (pypi uses PEP 440, npm uses node-semver, Go uses its own scheme). Start with pypi + npm; expand ecosystem coverage iteratively.

4. **Hosting for Phase 2?** Phase 1 is local-only. If this grows, evaluate Railway, Fly.io, or a small VPS for running the ingestion service 24/7.

---

## 15. Future Work (Phase 2 Preview)

These are explicitly out of scope for Phase 1 but inform architectural decisions:

- **Dependency manifest scanning:** Parse `requirements.txt`, `package.json`, etc. from a local directory and match against `affected_packages`.
- **Project registration:** Store scanned projects in the database with their dependency lists.
- **Continuous monitoring:** When new CVEs arrive via ingestion, check them against registered projects and send notifications.
- **Web UI / API server:** FastAPI-based HTTP API with a simple dashboard.
- **Slack / Discord / Telegram notifications** for new critical findings.
- **SAST integration:** Wrap Semgrep or CodeQL for insecure code pattern detection (Phase 2+).
