"""enhanced osint models

Revision ID: enhanced_osint_models
Revises: 1615fbe45d5c
Create Date: 2025-01-27 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'enhanced_osint_models'
down_revision: Union[str, Sequence[str], None] = '1615fbe45d5c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema to add enhanced OSINT models."""
    
    # Create enum for reconnaissance categories
    op.execute("CREATE TYPE reconcategory AS ENUM ('DOMAIN_WHOIS', 'SUBDOMAIN_ENUMERATION', 'CERTIFICATE_TRANSPARENCY', 'PUBLIC_REPOSITORIES', 'SEARCH_ENGINE_DORKING', 'DATA_BREACHES', 'INFRASTRUCTURE_EXPOSURE', 'ARCHIVE_HISTORICAL', 'SOCIAL_MEDIA_OSINT', 'CLOUD_ASSETS')")
    
    # Create WHOIS records table
    op.create_table('whois_records',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('domain', sa.String(length=500), nullable=False),
        sa.Column('registrar', sa.String(length=255), nullable=True),
        sa.Column('registrant_name', sa.String(length=255), nullable=True),
        sa.Column('registrant_email', sa.String(length=255), nullable=True),
        sa.Column('registrant_organization', sa.String(length=255), nullable=True),
        sa.Column('creation_date', sa.String(length=50), nullable=True),
        sa.Column('expiration_date', sa.String(length=50), nullable=True),
        sa.Column('updated_date', sa.String(length=50), nullable=True),
        sa.Column('name_servers', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('status', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('raw_data', sa.Text(), nullable=True),
        sa.Column('passive_recon_result_id', sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(['passive_recon_result_id'], ['public.passive_recon_results.id'], ),
        sa.PrimaryKeyConstraint('id'),
        schema='public'
    )
    op.create_index('idx_whois_domain', 'whois_records', ['domain'], unique=False, schema='public')
    op.create_index('idx_whois_registrar', 'whois_records', ['registrar'], unique=False, schema='public')
    op.create_index('idx_whois_passive_recon', 'whois_records', ['passive_recon_result_id'], unique=False, schema='public')
    
    # Create certificate logs table
    op.create_table('certificate_logs',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('domain', sa.String(length=500), nullable=False),
        sa.Column('certificate_id', sa.String(length=255), nullable=True),
        sa.Column('issuer', sa.String(length=255), nullable=True),
        sa.Column('subject_alt_names', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('not_before', sa.String(length=50), nullable=True),
        sa.Column('not_after', sa.String(length=50), nullable=True),
        sa.Column('serial_number', sa.String(length=255), nullable=True),
        sa.Column('fingerprint', sa.String(length=255), nullable=True),
        sa.Column('log_index', sa.String(length=255), nullable=True),
        sa.Column('passive_recon_result_id', sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(['passive_recon_result_id'], ['public.passive_recon_results.id'], ),
        sa.PrimaryKeyConstraint('id'),
        schema='public'
    )
    op.create_index('idx_cert_domain', 'certificate_logs', ['domain'], unique=False, schema='public')
    op.create_index('idx_cert_issuer', 'certificate_logs', ['issuer'], unique=False, schema='public')
    op.create_index('idx_cert_passive_recon', 'certificate_logs', ['passive_recon_result_id'], unique=False, schema='public')
    
    # Create repository findings table
    op.create_table('repository_findings',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('platform', sa.String(length=50), nullable=False),
        sa.Column('repository_url', sa.String(length=500), nullable=True),
        sa.Column('file_path', sa.String(length=500), nullable=True),
        sa.Column('finding_type', sa.String(length=100), nullable=False),
        sa.Column('content', sa.Text(), nullable=True),
        sa.Column('line_number', sa.Integer(), nullable=True),
        sa.Column('commit_hash', sa.String(length=255), nullable=True),
        sa.Column('severity', sa.String(length=50), nullable=True),
        sa.Column('passive_recon_result_id', sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(['passive_recon_result_id'], ['public.passive_recon_results.id'], ),
        sa.PrimaryKeyConstraint('id'),
        schema='public'
    )
    op.create_index('idx_repo_platform', 'repository_findings', ['platform'], unique=False, schema='public')
    op.create_index('idx_repo_type', 'repository_findings', ['finding_type'], unique=False, schema='public')
    op.create_index('idx_repo_passive_recon', 'repository_findings', ['passive_recon_result_id'], unique=False, schema='public')
    
    # Create search dork results table
    op.create_table('search_dork_results',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('search_query', sa.String(length=500), nullable=False),
        sa.Column('result_type', sa.String(length=100), nullable=False),
        sa.Column('url', sa.String(length=500), nullable=True),
        sa.Column('title', sa.String(length=500), nullable=True),
        sa.Column('snippet', sa.Text(), nullable=True),
        sa.Column('file_type', sa.String(length=50), nullable=True),
        sa.Column('file_size', sa.String(length=50), nullable=True),
        sa.Column('passive_recon_result_id', sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(['passive_recon_result_id'], ['public.passive_recon_results.id'], ),
        sa.PrimaryKeyConstraint('id'),
        schema='public'
    )
    op.create_index('idx_dork_query', 'search_dork_results', ['search_query'], unique=False, schema='public')
    op.create_index('idx_dork_type', 'search_dork_results', ['result_type'], unique=False, schema='public')
    op.create_index('idx_dork_passive_recon', 'search_dork_results', ['passive_recon_result_id'], unique=False, schema='public')
    
    # Create breach records table
    op.create_table('breach_records',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('breach_source', sa.String(length=255), nullable=False),
        sa.Column('breach_type', sa.String(length=100), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=True),
        sa.Column('username', sa.String(length=255), nullable=True),
        sa.Column('password_hash', sa.String(length=255), nullable=True),
        sa.Column('personal_info', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('breach_date', sa.String(length=50), nullable=True),
        sa.Column('breach_name', sa.String(length=255), nullable=True),
        sa.Column('severity', sa.String(length=50), nullable=True),
        sa.Column('passive_recon_result_id', sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(['passive_recon_result_id'], ['public.passive_recon_results.id'], ),
        sa.PrimaryKeyConstraint('id'),
        schema='public'
    )
    op.create_index('idx_breach_source', 'breach_records', ['breach_source'], unique=False, schema='public')
    op.create_index('idx_breach_type', 'breach_records', ['breach_type'], unique=False, schema='public')
    op.create_index('idx_breach_passive_recon', 'breach_records', ['passive_recon_result_id'], unique=False, schema='public')
    
    # Create infrastructure exposures table
    op.create_table('infrastructure_exposures',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('source', sa.String(length=50), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('port', sa.Integer(), nullable=True),
        sa.Column('service', sa.String(length=100), nullable=True),
        sa.Column('banner', sa.Text(), nullable=True),
        sa.Column('ssl_info', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('vulnerabilities', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('location', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('organization', sa.String(length=255), nullable=True),
        sa.Column('passive_recon_result_id', sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(['passive_recon_result_id'], ['public.passive_recon_results.id'], ),
        sa.PrimaryKeyConstraint('id'),
        schema='public'
    )
    op.create_index('idx_infra_source', 'infrastructure_exposures', ['source'], unique=False, schema='public')
    op.create_index('idx_infra_service', 'infrastructure_exposures', ['service'], unique=False, schema='public')
    op.create_index('idx_infra_passive_recon', 'infrastructure_exposures', ['passive_recon_result_id'], unique=False, schema='public')
    
    # Create archive findings table
    op.create_table('archive_findings',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('archive_source', sa.String(length=50), nullable=False),
        sa.Column('finding_type', sa.String(length=100), nullable=False),
        sa.Column('original_url', sa.String(length=500), nullable=True),
        sa.Column('archived_url', sa.String(length=500), nullable=True),
        sa.Column('archive_date', sa.String(length=50), nullable=True),
        sa.Column('content', sa.Text(), nullable=True),
        sa.Column('parameters', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('secrets_found', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('passive_recon_result_id', sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(['passive_recon_result_id'], ['public.passive_recon_results.id'], ),
        sa.PrimaryKeyConstraint('id'),
        schema='public'
    )
    op.create_index('idx_archive_source', 'archive_findings', ['archive_source'], unique=False, schema='public')
    op.create_index('idx_archive_type', 'archive_findings', ['finding_type'], unique=False, schema='public')
    op.create_index('idx_archive_passive_recon', 'archive_findings', ['passive_recon_result_id'], unique=False, schema='public')
    
    # Create social media intel table
    op.create_table('social_media_intel',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('platform', sa.String(length=50), nullable=False),
        sa.Column('intel_type', sa.String(length=100), nullable=False),
        sa.Column('username', sa.String(length=255), nullable=True),
        sa.Column('profile_url', sa.String(length=500), nullable=True),
        sa.Column('content', sa.Text(), nullable=True),
        sa.Column('intel_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('relevance_score', sa.Integer(), nullable=True),
        sa.Column('passive_recon_result_id', sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(['passive_recon_result_id'], ['public.passive_recon_results.id'], ),
        sa.PrimaryKeyConstraint('id'),
        schema='public'
    )
    op.create_index('idx_social_platform', 'social_media_intel', ['platform'], unique=False, schema='public')
    op.create_index('idx_social_type', 'social_media_intel', ['intel_type'], unique=False, schema='public')
    op.create_index('idx_social_passive_recon', 'social_media_intel', ['passive_recon_result_id'], unique=False, schema='public')
    
    # Create cloud assets table
    op.create_table('cloud_assets',
        sa.Column('id', sa.UUID(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('provider', sa.String(length=50), nullable=False),
        sa.Column('asset_type', sa.String(length=100), nullable=False),
        sa.Column('asset_name', sa.String(length=255), nullable=True),
        sa.Column('asset_url', sa.String(length=500), nullable=True),
        sa.Column('is_public', sa.Boolean(), nullable=False),
        sa.Column('permissions', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('contents', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('misconfiguration', sa.Text(), nullable=True),
        sa.Column('passive_recon_result_id', sa.UUID(), nullable=False),
        sa.ForeignKeyConstraint(['passive_recon_result_id'], ['public.passive_recon_results.id'], ),
        sa.PrimaryKeyConstraint('id'),
        schema='public'
    )
    op.create_index('idx_cloud_provider', 'cloud_assets', ['provider'], unique=False, schema='public')
    op.create_index('idx_cloud_type', 'cloud_assets', ['asset_type'], unique=False, schema='public')
    op.create_index('idx_cloud_passive_recon', 'cloud_assets', ['passive_recon_result_id'], unique=False, schema='public')


def downgrade() -> None:
    """Downgrade schema to remove enhanced OSINT models."""
    
    # Drop tables in reverse order
    op.drop_table('cloud_assets', schema='public')
    op.drop_table('social_media_intel', schema='public')
    op.drop_table('archive_findings', schema='public')
    op.drop_table('infrastructure_exposures', schema='public')
    op.drop_table('breach_records', schema='public')
    op.drop_table('search_dork_results', schema='public')
    op.drop_table('repository_findings', schema='public')
    op.drop_table('certificate_logs', schema='public')
    op.drop_table('whois_records', schema='public')
    
    # Drop enum
    op.execute("DROP TYPE reconcategory")