-- PostgreSQL initialization script for Bug Hunting Framework
-- This script runs when the database container starts for the first time

-- Create database if it doesn't exist (handled by POSTGRES_DB env var)
-- Create extensions that might be needed
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Set timezone
SET timezone = 'UTC';

-- Create any additional users or schemas if needed
-- (Django will handle table creation via migrations) 