-- Create admin user with password 'admin123'
INSERT INTO users (id, email, password_hash, first_name, last_name, company_name, role, subscription_tier, is_active, email_verified, created_at, updated_at) 
VALUES (uuid_generate_v4(), 'admin@cybertoolkit.com', '$2a$12$bogdyu7UPcVZTQ2VStDJquZxhMjdX1xU63rJwYjsFJGxvzbox3DAW', 'Admin', 'User', 'CyberToolkit', 'admin', 'enterprise', true, true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

-- Create test user with password 'password'
INSERT INTO users (id, email, password_hash, first_name, last_name, company_name, role, subscription_tier, is_active, email_verified, created_at, updated_at) 
VALUES (uuid_generate_v4(), 'test@cybertoolkit.com', '$2a$12$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Test', 'User', 'CyberToolkit', 'user', 'free', true, true, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
