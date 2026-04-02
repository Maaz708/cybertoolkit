-- CyberToolkit Database Setup
-- Run this script in PostgreSQL to create the database and schema

-- Create the main database
CREATE DATABASE cybertoolkit;

-- Connect to the new database
\c cybertoolkit;

-- Create the complete schema (this will be run automatically by the setup script)
-- The schema includes all tables: users, network_scans, network_connections, 
-- file_scans, email_analyses, alerts, user_sessions, api_usage, system_metrics

-- You can now run the schema.sql file or use the automated setup script
