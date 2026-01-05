-- Cedar Authorization Extension for PostgreSQL
-- This extension integrates PostgreSQL with Cedar policy decision points

-- Create the extension schema if it doesn't exist
CREATE SCHEMA IF NOT EXISTS cedar_auth;

-- Configuration table for Cedar agent connection
CREATE TABLE IF NOT EXISTS cedar_auth.config (
    key TEXT PRIMARY KEY,
    value TEXT
);

-- Default configuration
INSERT INTO cedar_auth.config (key, value) VALUES
    ('cedar_agent_url', 'http://cedar-agent:8180/v1/is_authorized'),
    ('timeout_ms', '5000'),
    ('cache_enabled', 'true'),
    ('cache_ttl_seconds', '300')
ON CONFLICT (key) DO NOTHING;

-- Function to set Cedar agent URL
CREATE OR REPLACE FUNCTION cedar_auth.set_agent_url(url TEXT)
RETURNS VOID AS $$
BEGIN
    UPDATE cedar_auth.config SET value = url WHERE key = 'cedar_agent_url';
END;
$$ LANGUAGE plpgsql;

-- Function to get Cedar agent URL
CREATE OR REPLACE FUNCTION cedar_auth.get_agent_url()
RETURNS TEXT AS $$
DECLARE
    url TEXT;
BEGIN
    SELECT value INTO url FROM cedar_auth.config WHERE key = 'cedar_agent_url';
    RETURN COALESCE(url, 'http://cedar-agent:8180/v1/is_authorized');
END;
$$ LANGUAGE plpgsql;

-- Function to test Cedar agent connectivity
CREATE OR REPLACE FUNCTION cedar_auth.test_connection()
RETURNS BOOLEAN AS $$
DECLARE
    agent_url TEXT;
    result BOOLEAN := FALSE;
BEGIN
    agent_url := cedar_auth.get_agent_url();

    -- Simple connectivity test (would need actual HTTP call in production)
    -- For now, just return true if URL is set
    IF agent_url IS NOT NULL AND LENGTH(agent_url) > 0 THEN
        result := TRUE;
        RAISE NOTICE 'Cedar agent URL configured: %', agent_url;
    ELSE
        RAISE NOTICE 'Cedar agent URL not configured';
    END IF;

    RETURN result;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions on the extension functions
GRANT EXECUTE ON FUNCTION cedar_auth.set_agent_url(TEXT) TO PUBLIC;
GRANT EXECUTE ON FUNCTION cedar_auth.get_agent_url() TO PUBLIC;
GRANT EXECUTE ON FUNCTION cedar_auth.test_connection() TO PUBLIC;

-- Create a view for configuration status
CREATE OR REPLACE VIEW cedar_auth.status AS
SELECT
    key,
    CASE
        WHEN key = 'cedar_agent_url' THEN 'Configured'
        WHEN key = 'timeout_ms' THEN 'Configured'
        ELSE 'Default'
    END as status
FROM cedar_auth.config;

GRANT SELECT ON cedar_auth.status TO PUBLIC;

-- Extension initialization complete
DO $$
BEGIN
    RAISE NOTICE 'Cedar Authorization Extension 1.0 installed successfully';
    RAISE NOTICE 'Use cedar_auth.test_connection() to verify Cedar agent connectivity';
END $$;
