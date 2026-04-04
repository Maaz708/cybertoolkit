-- 🗄️ DISABLE RLS FOR INITIAL DEPLOYMENT
-- Run this in Supabase SQL Editor first

-- Disable Row Level Security on all tables
ALTER TABLE users DISABLE ROW LEVEL SECURITY;
ALTER TABLE network_scans DISABLE ROW LEVEL SECURITY;
ALTER TABLE network_connections DISABLE ROW LEVEL SECURITY;
ALTER TABLE file_scans DISABLE ROW LEVEL SECURITY;
ALTER TABLE email_analyses DISABLE ROW LEVEL SECURITY;
ALTER TABLE alerts DISABLE ROW LEVEL SECURITY;
ALTER TABLE api_usage DISABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions DISABLE ROW LEVEL SECURITY;
ALTER TABLE system_metrics DISABLE ROW LEVEL SECURITY;

-- Drop RLS policies (they'll be re-enabled later)
DROP POLICY IF EXISTS users_isolation ON users;
DROP POLICY IF EXISTS network_scans_user_policy ON network_scans;
DROP POLICY IF EXISTS network_connections_user_policy ON network_connections;
DROP POLICY IF EXISTS file_scans_user_policy ON file_scans;
DROP POLICY IF EXISTS email_analyses_user_policy ON email_analyses;
DROP POLICY IF EXISTS alerts_user_policy ON alerts;
DROP POLICY IF EXISTS api_usage_user_policy ON api_usage;

-- Insert default admin user
INSERT INTO users (email, password_hash, first_name, last_name, role, is_active, email_verified)
VALUES (
    'admin@cybertoolkit.com',
    '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJ2k',
    'Admin',
    'User',
    'admin',
    true,
    true
) ON CONFLICT (email) DO NOTHING;

-- Success message
SELECT 'RLS Disabled and admin user created successfully' as result;
