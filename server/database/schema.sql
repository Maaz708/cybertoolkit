-- 🗄️ CyberToolkit Production Database Schema
-- PostgreSQL Schema for Multi-Tenant SaaS Platform

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table for authentication and user management
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    company_name VARCHAR(255),
    role VARCHAR(50) DEFAULT 'user' CHECK (role IN ('admin', 'user', 'enterprise')),
    subscription_tier VARCHAR(50) DEFAULT 'free' CHECK (subscription_tier IN ('free', 'pro', 'enterprise')),
    is_active BOOLEAN DEFAULT true,
    email_verified BOOLEAN DEFAULT false,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Enable Row Level Security
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Create policy for users to only see their own data
CREATE POLICY users_isolation ON users
    USING (id = current_setting('app.current_user_id', true)::uuid)
    FOR ALL
    WITH CHECK (id IS NOT NULL);

-- Apply the policy
ALTER TABLE users FORCE ROW LEVEL SECURITY;

-- Network scans table for storing network monitoring sessions
CREATE TABLE network_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scan_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'stopped')),
    interval_ms INTEGER DEFAULT 3000,
    duration_seconds INTEGER,
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    total_connections_found INTEGER DEFAULT 0,
    threats_detected INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Network connections table for storing connection data
CREATE TABLE network_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID NOT NULL REFERENCES network_scans(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    protocol VARCHAR(10) NOT NULL CHECK (protocol IN ('TCP', 'UDP', 'Other')),
    local_address VARCHAR(45) NOT NULL,
    local_port INTEGER,
    remote_address VARCHAR(45),
    remote_port INTEGER,
    state VARCHAR(20),
    process_id INTEGER,
    process_name VARCHAR(255),
    is_suspicious BOOLEAN DEFAULT false,
    threat_level VARCHAR(20) DEFAULT 'low' CHECK (threat_level IN ('low', 'medium', 'high', 'critical')),
    country_code VARCHAR(2),
    city VARCHAR(100),
    metadata JSONB DEFAULT '{}',
    captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- File analysis scans table
CREATE TABLE file_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    original_filename VARCHAR(255) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    file_size BIGINT NOT NULL,
    file_hash VARCHAR(64),
    mime_type VARCHAR(100),
    scan_type VARCHAR(50) DEFAULT 'malware' CHECK (scan_type IN ('malware', 'forensic', 'metadata')),
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    threats_found INTEGER DEFAULT 0,
    is_malicious BOOLEAN DEFAULT false,
    scan_results JSONB DEFAULT '{}',
    extracted_metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Email analysis table
CREATE TABLE email_analyses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    subject VARCHAR(500),
    sender_email VARCHAR(255),
    recipient_emails TEXT[],
    analysis_type VARCHAR(50) DEFAULT 'phishing' CHECK (analysis_type IN ('phishing', 'spam', 'malware', 'forensic')),
    status VARCHAR(50) DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    is_phishing BOOLEAN DEFAULT false,
    is_spam BOOLEAN DEFAULT false,
    is_malicious BOOLEAN DEFAULT false,
    confidence_score DECIMAL(5,2),
    email_headers JSONB DEFAULT '{}',
    analysis_results JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE
);

-- Alerts table for security notifications
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    alert_type VARCHAR(50) NOT NULL CHECK (alert_type IN ('network', 'malware', 'email', 'system')),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    source_table VARCHAR(50), -- network_scans, file_scans, email_analyses
    source_id UUID,
    is_read BOOLEAN DEFAULT false,
    is_resolved BOOLEAN DEFAULT false,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP WITH TIME ZONE
);

-- User sessions table for JWT token management
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    device_info JSONB DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- API usage tracking for rate limiting and billing
CREATE TABLE api_usage (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status_code INTEGER NOT NULL,
    response_time_ms INTEGER,
    ip_address INET,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- System metrics for monitoring
CREATE TABLE system_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    metric_type VARCHAR(50) NOT NULL CHECK (metric_type IN ('active_users', 'scans_per_hour', 'threats_detected', 'api_requests')),
    metric_value BIGINT NOT NULL,
    metadata JSONB DEFAULT '{}',
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance optimization
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_active ON users(is_active);
CREATE INDEX idx_network_scans_user_id ON network_scans(user_id);
CREATE INDEX idx_network_scans_status ON network_scans(status);
CREATE INDEX idx_network_scans_created_at ON network_scans(created_at);
CREATE INDEX idx_network_connections_scan_id ON network_connections(scan_id);
CREATE INDEX idx_network_connections_user_id ON network_connections(user_id);
CREATE INDEX idx_network_connections_suspicious ON network_connections(is_suspicious);
CREATE INDEX idx_network_connections_captured_at ON network_connections(captured_at);
CREATE INDEX idx_file_scans_user_id ON file_scans(user_id);
CREATE INDEX idx_file_scans_status ON file_scans(status);
CREATE INDEX idx_file_scans_malicious ON file_scans(is_malicious);
CREATE INDEX idx_email_analyses_user_id ON email_analyses(user_id);
CREATE INDEX idx_email_analyses_status ON email_analyses(status);
CREATE INDEX idx_email_analyses_phishing ON email_analyses(is_phishing);
CREATE INDEX idx_alerts_user_id ON alerts(user_id);
CREATE INDEX idx_alerts_unread ON alerts(user_id, is_read);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_active ON user_sessions(is_active);
CREATE INDEX idx_user_sessions_expires_at ON user_sessions(expires_at);
CREATE INDEX idx_api_usage_user_id ON api_usage(user_id);
CREATE INDEX idx_api_usage_created_at ON api_usage(created_at);
CREATE INDEX idx_system_metrics_type ON system_metrics(metric_type);
CREATE INDEX idx_system_metrics_recorded_at ON system_metrics(recorded_at);

-- Row Level Security (RLS) for multi-tenant isolation
ALTER TABLE network_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE network_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE file_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_analyses ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_usage ENABLE ROW LEVEL SECURITY;

-- RLS Policies - Users can only access their own data
CREATE POLICY network_scans_user_policy ON network_scans
    FOR ALL TO authenticated_user
    USING (user_id = current_setting('app.current_user_id')::uuid);

CREATE POLICY network_connections_user_policy ON network_connections
    FOR ALL TO authenticated_user
    USING (user_id = current_setting('app.current_user_id')::uuid);

CREATE POLICY file_scans_user_policy ON file_scans
    FOR ALL TO authenticated_user
    USING (user_id = current_setting('app.current_user_id')::uuid);

CREATE POLICY email_analyses_user_policy ON email_analyses
    FOR ALL TO authenticated_user
    USING (user_id = current_setting('app.current_user_id')::uuid);

CREATE POLICY alerts_user_policy ON alerts
    FOR ALL TO authenticated_user
    USING (user_id = current_setting('app.current_user_id')::uuid);

CREATE POLICY api_usage_user_policy ON api_usage
    FOR ALL TO authenticated_user
    USING (user_id = current_setting('app.current_user_id')::uuid);

-- Create authenticated_user role for RLS
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'authenticated_user') THEN
        CREATE ROLE authenticated_user;
    END IF;
END
$$;
