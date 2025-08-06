#!/bin/bash

# Production Backup Script for Bug Hunting Framework
# Automated backup with encryption, compression, and retention management

set -euo pipefail

# Configuration
BACKUP_DIR="/backups"
RETENTION_DAYS=${BACKUP_RETENTION_DAYS:-30}
COMPRESSION=${BACKUP_COMPRESSION:-true}
ENCRYPTION=${BACKUP_ENCRYPTION:-true}
ENCRYPTION_KEY_FILE="/backups/encryption.key"
LOG_FILE="/backups/backup.log"

# Database configuration
DB_HOST=${POSTGRES_HOST:-db}
DB_PORT=${POSTGRES_PORT:-5432}
DB_NAME=${POSTGRES_DB:-bug_hunting_framework}
DB_USER=${POSTGRES_USER:-bug_hunting_user}
DB_PASSWORD=${POSTGRES_PASSWORD}

# Timestamp for backup files
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_DATE=$(date +"%Y-%m-%d")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    log "${RED}ERROR: $1${NC}"
    exit 1
}

# Success message
success() {
    log "${GREEN}SUCCESS: $1${NC}"
}

# Warning message
warning() {
    log "${YELLOW}WARNING: $1${NC}"
}

# Check if required environment variables are set
check_environment() {
    log "Checking environment configuration..."
    
    if [[ -z "$DB_PASSWORD" ]]; then
        error_exit "Database password not set"
    fi
    
    if [[ ! -d "$BACKUP_DIR" ]]; then
        error_exit "Backup directory $BACKUP_DIR does not exist"
    fi
    
    success "Environment configuration validated"
}

# Create backup directory structure
create_backup_dirs() {
    log "Creating backup directory structure..."
    
    mkdir -p "$BACKUP_DIR/database"
    mkdir -p "$BACKUP_DIR/files"
    mkdir -p "$BACKUP_DIR/logs"
    mkdir -p "$BACKUP_DIR/config"
    mkdir -p "$BACKUP_DIR/encrypted"
    
    success "Backup directory structure created"
}

# Generate encryption key if not exists
generate_encryption_key() {
    if [[ "$ENCRYPTION" == "true" ]]; then
        log "Setting up encryption..."
        
        if [[ ! -f "$ENCRYPTION_KEY_FILE" ]]; then
            log "Generating new encryption key..."
            openssl rand -hex 32 > "$ENCRYPTION_KEY_FILE"
            chmod 600 "$ENCRYPTION_KEY_FILE"
            success "Encryption key generated"
        else
            log "Using existing encryption key"
        fi
    fi
}

# Backup database
backup_database() {
    log "Starting database backup..."
    
    local db_backup_file="$BACKUP_DIR/database/db_backup_${TIMESTAMP}.sql"
    local db_backup_compressed="$db_backup_file.gz"
    
    # Create database backup
    PGPASSWORD="$DB_PASSWORD" pg_dump \
        -h "$DB_HOST" \
        -p "$DB_PORT" \
        -U "$DB_USER" \
        -d "$DB_NAME" \
        --verbose \
        --no-password \
        --clean \
        --if-exists \
        --create \
        --format=plain \
        --file="$db_backup_file" 2>> "$LOG_FILE"
    
    if [[ $? -eq 0 ]]; then
        success "Database backup created: $db_backup_file"
        
        # Compress backup if enabled
        if [[ "$COMPRESSION" == "true" ]]; then
            log "Compressing database backup..."
            gzip "$db_backup_file"
            db_backup_file="$db_backup_compressed"
            success "Database backup compressed: $db_backup_file"
        fi
        
        # Encrypt backup if enabled
        if [[ "$ENCRYPTION" == "true" ]]; then
            log "Encrypting database backup..."
            local encrypted_file="$BACKUP_DIR/encrypted/db_backup_${TIMESTAMP}.sql.gz.enc"
            openssl enc -aes-256-cbc -salt \
                -in "$db_backup_file" \
                -out "$encrypted_file" \
                -pass file:"$ENCRYPTION_KEY_FILE"
            
            if [[ $? -eq 0 ]]; then
                rm "$db_backup_file"
                success "Database backup encrypted: $encrypted_file"
            else
                error_exit "Failed to encrypt database backup"
            fi
        fi
    else
        error_exit "Database backup failed"
    fi
}

# Backup application files
backup_files() {
    log "Starting application files backup..."
    
    local files_backup="$BACKUP_DIR/files/files_backup_${TIMESTAMP}.tar"
    local files_backup_compressed="$files_backup.gz"
    
    # Create files backup (excluding logs and temporary files)
    tar --exclude='*.log' \
        --exclude='*.tmp' \
        --exclude='__pycache__' \
        --exclude='node_modules' \
        --exclude='.git' \
        --exclude='.env' \
        -cf "$files_backup" \
        /app 2>> "$LOG_FILE"
    
    if [[ $? -eq 0 ]]; then
        success "Application files backup created: $files_backup"
        
        # Compress backup if enabled
        if [[ "$COMPRESSION" == "true" ]]; then
            log "Compressing files backup..."
            gzip "$files_backup"
            files_backup="$files_backup_compressed"
            success "Files backup compressed: $files_backup"
        fi
        
        # Encrypt backup if enabled
        if [[ "$ENCRYPTION" == "true" ]]; then
            log "Encrypting files backup..."
            local encrypted_file="$BACKUP_DIR/encrypted/files_backup_${TIMESTAMP}.tar.gz.enc"
            openssl enc -aes-256-cbc -salt \
                -in "$files_backup" \
                -out "$encrypted_file" \
                -pass file:"$ENCRYPTION_KEY_FILE"
            
            if [[ $? -eq 0 ]]; then
                rm "$files_backup"
                success "Files backup encrypted: $encrypted_file"
            else
                error_exit "Failed to encrypt files backup"
            fi
        fi
    else
        error_exit "Files backup failed"
    fi
}

# Backup configuration files
backup_config() {
    log "Starting configuration backup..."
    
    local config_backup="$BACKUP_DIR/config/config_backup_${TIMESTAMP}.tar"
    local config_backup_compressed="$config_backup.gz"
    
    # Create configuration backup
    tar -cf "$config_backup" \
        /etc/nginx/nginx.conf \
        /etc/nginx/conf.d \
        /app/settings.py \
        /app/requirements.txt \
        /app/package.json \
        /app/next.config.js 2>> "$LOG_FILE"
    
    if [[ $? -eq 0 ]]; then
        success "Configuration backup created: $config_backup"
        
        # Compress backup if enabled
        if [[ "$COMPRESSION" == "true" ]]; then
            log "Compressing configuration backup..."
            gzip "$config_backup"
            config_backup="$config_backup_compressed"
            success "Configuration backup compressed: $config_backup"
        fi
        
        # Encrypt backup if enabled
        if [[ "$ENCRYPTION" == "true" ]]; then
            log "Encrypting configuration backup..."
            local encrypted_file="$BACKUP_DIR/encrypted/config_backup_${TIMESTAMP}.tar.gz.enc"
            openssl enc -aes-256-cbc -salt \
                -in "$config_backup" \
                -out "$encrypted_file" \
                -pass file:"$ENCRYPTION_KEY_FILE"
            
            if [[ $? -eq 0 ]]; then
                rm "$config_backup"
                success "Configuration backup encrypted: $encrypted_file"
            else
                error_exit "Failed to encrypt configuration backup"
            fi
        fi
    else
        error_exit "Configuration backup failed"
    fi
}

# Backup logs
backup_logs() {
    log "Starting logs backup..."
    
    local logs_backup="$BACKUP_DIR/logs/logs_backup_${TIMESTAMP}.tar"
    local logs_backup_compressed="$logs_backup.gz"
    
    # Create logs backup
    tar -cf "$logs_backup" \
        /app/logs \
        /var/log/nginx \
        /var/log/postgresql 2>> "$LOG_FILE"
    
    if [[ $? -eq 0 ]]; then
        success "Logs backup created: $logs_backup"
        
        # Compress backup if enabled
        if [[ "$COMPRESSION" == "true" ]]; then
            log "Compressing logs backup..."
            gzip "$logs_backup"
            logs_backup="$logs_backup_compressed"
            success "Logs backup compressed: $logs_backup"
        fi
        
        # Encrypt backup if enabled
        if [[ "$ENCRYPTION" == "true" ]]; then
            log "Encrypting logs backup..."
            local encrypted_file="$BACKUP_DIR/encrypted/logs_backup_${TIMESTAMP}.tar.gz.enc"
            openssl enc -aes-256-cbc -salt \
                -in "$logs_backup" \
                -out "$encrypted_file" \
                -pass file:"$ENCRYPTION_KEY_FILE"
            
            if [[ $? -eq 0 ]]; then
                rm "$logs_backup"
                success "Logs backup encrypted: $encrypted_file"
            else
                error_exit "Failed to encrypt logs backup"
            fi
        fi
    else
        error_exit "Logs backup failed"
    fi
}

# Create backup manifest
create_manifest() {
    log "Creating backup manifest..."
    
    local manifest_file="$BACKUP_DIR/backup_manifest_${TIMESTAMP}.json"
    
    cat > "$manifest_file" << EOF
{
    "backup_id": "${TIMESTAMP}",
    "backup_date": "${BACKUP_DATE}",
    "backup_time": "$(date -Iseconds)",
    "environment": "production",
    "framework_version": "1.0.0",
    "backup_config": {
        "compression": ${COMPRESSION},
        "encryption": ${ENCRYPTION},
        "retention_days": ${RETENTION_DAYS}
    },
    "backup_components": {
        "database": "db_backup_${TIMESTAMP}.sql.gz${ENCRYPTION:+.enc}",
        "files": "files_backup_${TIMESTAMP}.tar.gz${ENCRYPTION:+.enc}",
        "config": "config_backup_${TIMESTAMP}.tar.gz${ENCRYPTION:+.enc}",
        "logs": "logs_backup_${TIMESTAMP}.tar.gz${ENCRYPTION:+.enc}"
    },
    "system_info": {
        "hostname": "$(hostname)",
        "kernel": "$(uname -r)",
        "disk_usage": "$(df -h /backups | tail -1 | awk '{print $5}')",
        "backup_size": "$(du -sh /backups/encrypted 2>/dev/null | cut -f1 || echo 'N/A')"
    }
}
EOF
    
    success "Backup manifest created: $manifest_file"
}

# Clean up old backups
cleanup_old_backups() {
    log "Cleaning up old backups (older than ${RETENTION_DAYS} days)..."
    
    local deleted_count=0
    
    # Find and delete old backup files
    find "$BACKUP_DIR" -name "*.sql*" -mtime +$RETENTION_DAYS -delete
    find "$BACKUP_DIR" -name "*.tar*" -mtime +$RETENTION_DAYS -delete
    find "$BACKUP_DIR" -name "backup_manifest_*.json" -mtime +$RETENTION_DAYS -delete
    
    deleted_count=$(find "$BACKUP_DIR" -name "*.sql*" -mtime +$RETENTION_DAYS | wc -l)
    deleted_count=$((deleted_count + $(find "$BACKUP_DIR" -name "*.tar*" -mtime +$RETENTION_DAYS | wc -l)))
    
    if [[ $deleted_count -gt 0 ]]; then
        success "Cleaned up $deleted_count old backup files"
    else
        log "No old backup files to clean up"
    fi
}

# Verify backup integrity
verify_backup() {
    log "Verifying backup integrity..."
    
    local verification_failed=false
    
    # Check if backup files exist
    for component in database files config logs; do
        local backup_pattern="$BACKUP_DIR/encrypted/${component}_backup_${TIMESTAMP}.*"
        if ! ls $backup_pattern >/dev/null 2>&1; then
            warning "Backup file for $component not found"
            verification_failed=true
        fi
    done
    
    # Check backup file sizes
    for backup_file in "$BACKUP_DIR"/encrypted/*_backup_${TIMESTAMP}.*; do
        if [[ -f "$backup_file" ]]; then
            local file_size=$(stat -c%s "$backup_file")
            if [[ $file_size -eq 0 ]]; then
                warning "Backup file $backup_file is empty"
                verification_failed=true
            fi
        fi
    done
    
    if [[ "$verification_failed" == "true" ]]; then
        error_exit "Backup verification failed"
    else
        success "Backup verification completed successfully"
    fi
}

# Send backup notification
send_notification() {
    log "Sending backup notification..."
    
    local backup_size=$(du -sh /backups/encrypted 2>/dev/null | cut -f1 || echo 'N/A')
    local notification_message="Backup completed successfully at $(date)
    
Backup Details:
- Backup ID: ${TIMESTAMP}
- Date: ${BACKUP_DATE}
- Size: ${backup_size}
- Components: Database, Files, Config, Logs
- Encryption: ${ENCRYPTION}
- Compression: ${COMPRESSION}
- Retention: ${RETENTION_DAYS} days

Backup location: ${BACKUP_DIR}/encrypted/"
    
    # Log notification (in production, this would send to monitoring system)
    log "Backup notification: $notification_message"
    success "Backup notification sent"
}

# Main backup function
main() {
    log "=== Starting Bug Hunting Framework Backup ==="
    log "Backup ID: ${TIMESTAMP}"
    log "Date: ${BACKUP_DATE}"
    
    # Execute backup steps
    check_environment
    create_backup_dirs
    generate_encryption_key
    backup_database
    backup_files
    backup_config
    backup_logs
    create_manifest
    verify_backup
    cleanup_old_backups
    send_notification
    
    log "=== Backup completed successfully ==="
    success "All backup operations completed successfully"
}

# Execute main function
main "$@" 