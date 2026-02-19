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

CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_published ON vulnerabilities(published_at DESC);
CREATE INDEX IF NOT EXISTS idx_vuln_epss ON vulnerabilities(epss_score DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_vuln_kev ON vulnerabilities(cisa_kev) WHERE cisa_kev = TRUE;
CREATE INDEX IF NOT EXISTS idx_affected_pkg_ecosystem ON affected_packages(ecosystem, package_name);
CREATE INDEX IF NOT EXISTS idx_affected_pkg_cve ON affected_packages(cve_id);
CREATE INDEX IF NOT EXISTS idx_exploits_cve ON exploits(cve_id);
