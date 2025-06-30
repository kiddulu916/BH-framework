"""add extra_metadata to passive_recon_result and subdomain

Revision ID: b99c9106da21
Revises: dc69dea9ba0a
Create Date: 2025-06-30 00:51:25.030819

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'b99c9106da21'
down_revision: Union[str, Sequence[str], None] = 'dc69dea9ba0a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.add_column('passive_recon_results', sa.Column('extra_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('subdomains', sa.Column('extra_metadata', postgresql.JSONB(astext_type=sa.Text()), nullable=True))

def downgrade() -> None:
    op.drop_column('passive_recon_results', 'extra_metadata')
    op.drop_column('subdomains', 'extra_metadata')

