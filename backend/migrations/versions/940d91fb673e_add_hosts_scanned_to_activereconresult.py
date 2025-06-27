"""Add hosts_scanned to ActiveReconResult

Revision ID: 940d91fb673e
Revises: 20240623_update_workflow_enums
Create Date: 2025-06-25 09:04:47.943327

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '940d91fb673e'
down_revision: Union[str, Sequence[str], None] = '20240623_update_workflow_enums'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('active_recon_results', sa.Column('hosts_scanned', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('active_recon_results', 'hosts_scanned')
