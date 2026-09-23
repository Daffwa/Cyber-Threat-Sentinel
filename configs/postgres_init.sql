-- ============================================================================
-- Enterprise Zero-Hour Cyber Threat & Phishing Sentinel DDL Schema
-- Database: cyber_threat_db
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Raw Stream Telemetry (All live certificates seen from CertStream)
CREATE TABLE IF NOT EXISTS certificates_stream (
    cert_id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    domain VARCHAR(255) NOT NULL,
    all_domains TEXT,
    issuer_ca VARCHAR(150),
    fingerprint VARCHAR(100),
    tld VARCHAR(30),
    shannon_entropy NUMERIC(5, 3),
    threat_verdict VARCHAR(50) DEFAULT 'BENIGN'
);

CREATE INDEX IF NOT EXISTS idx_cert_stream_timestamp ON certificates_stream(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_cert_stream_verdict ON certificates_stream(threat_verdict);
CREATE INDEX IF NOT EXISTS idx_cert_stream_tld ON certificates_stream(tld);

-- 2. Phishing & Threat Intelligence Detections (High-Value Alerts)
CREATE TABLE IF NOT EXISTS phishing_threats (
    threat_id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    domain VARCHAR(255) NOT NULL,
    target_brand VARCHAR(100) NOT NULL,
    threat_type VARCHAR(50) NOT NULL, -- BRAND_IMPERSONATION, TYPOSQUATTING, DGA_MALWARE_C2, SCAM_PHISHING
    threat_score NUMERIC(4, 2) NOT NULL, -- Scale 0.0 - 5.0
    confidence NUMERIC(5, 4) NOT NULL,   -- Scale 0.0 - 1.0
    shannon_entropy NUMERIC(5, 3) NOT NULL,
    levenshtein_distance INT,
    issuer_ca VARCHAR(150),
    action_taken VARCHAR(50) NOT NULL,  -- AUTO_SINKHOLE, FLAGGED_SOC
    processing_latency_ms NUMERIC(6, 3) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_phishing_timestamp ON phishing_threats(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_phishing_brand ON phishing_threats(target_brand);
CREATE INDEX IF NOT EXISTS idx_phishing_type ON phishing_threats(threat_type);

-- 3. Autonomous DNS RPZ Sinkhole & Firewall Blocks
CREATE TABLE IF NOT EXISTS sinkhole_blocks (
    block_id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    domain VARCHAR(255) NOT NULL,
    target_brand VARCHAR(100) NOT NULL,
    reason TEXT NOT NULL,
    rule_name VARCHAR(100) NOT NULL,
    execution_latency_ms NUMERIC(6, 3) NOT NULL,
    status VARCHAR(20) DEFAULT 'ENFORCED'
);

CREATE INDEX IF NOT EXISTS idx_sinkhole_timestamp ON sinkhole_blocks(timestamp DESC);

-- 4. Protected Brand Watchlist Directory
CREATE TABLE IF NOT EXISTS brand_watchlists (
    brand_id SERIAL PRIMARY KEY,
    brand_name VARCHAR(100) UNIQUE NOT NULL,
    category VARCHAR(50) NOT NULL,
    official_domains TEXT NOT NULL
);

INSERT INTO brand_watchlists (brand_name, category, official_domains) VALUES
    ('bca', 'Indonesian Bank', 'bca.co.id, klikbca.com, mybca.bca.co.id'),
    ('mandiri', 'Indonesian Bank', 'bankmandiri.co.id, livin.bankmandiri.co.id'),
    ('bri', 'Indonesian Bank', 'bri.co.id, brimo.bri.co.id'),
    ('bni', 'Indonesian Bank', 'bni.co.id, bni-mobilebanking.bni.co.id'),
    ('cimb', 'Indonesian Bank', 'cimbniaga.co.id, octomobile.co.id'),
    ('permata', 'Indonesian Bank', 'permatabank.com'),
    ('bsi', 'Indonesian Bank', 'bankbsi.co.id'),
    ('gopay', 'Indonesian Fintech', 'gopay.co.id, gojek.com'),
    ('ovo', 'Indonesian Fintech', 'ovo.id'),
    ('dana', 'Indonesian Fintech', 'dana.id'),
    ('shopee', 'E-Commerce', 'shopee.co.id, shopee.com, shopeepay.co.id'),
    ('tokopedia', 'E-Commerce', 'tokopedia.com'),
    ('blibli', 'E-Commerce', 'blibli.com'),
    ('telkomsel', 'Telecommunications', 'telkomsel.com, mytelkomsel.com'),
    ('indodax', 'Crypto Exchange', 'indodax.com'),
    ('tokocrypto', 'Crypto Exchange', 'tokocrypto.com'),
    ('google', 'Global Tech', 'google.com, accounts.google.com'),
    ('microsoft', 'Global Tech', 'microsoft.com, login.live.com, office.com'),
    ('paypal', 'Global Payments', 'paypal.com'),
    ('apple', 'Global Tech', 'apple.com, icloud.com'),
    ('netflix', 'Streaming Media', 'netflix.com')
ON CONFLICT (brand_name) DO NOTHING;
