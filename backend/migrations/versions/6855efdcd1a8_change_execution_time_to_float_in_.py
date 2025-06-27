"""Change execution_time to Float in ActiveReconResult

Revision ID: 6855efdcd1a8
Revises: 940d91fb673e
Create Date: 2025-06-25 09:50:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '6855efdcd1a8'
down_revision: Union[str, Sequence[str], None] = '940d91fb673e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.alter_column('active_recon_results', 'execution_time',
        existing_type=sa.String(length=50),
        type_=sa.Float(),
        schema='public',
        existing_nullable=True,
        postgresql_using="execution_time::double precision"
    )

def downgrade() -> None:
    op.alter_column('active_recon_results', 'execution_time',
        existing_type=sa.Float(),
        type_=sa.String(length=50),
        schema='public',
        existing_nullable=True,
        postgresql_using="execution_time::text"
    )
