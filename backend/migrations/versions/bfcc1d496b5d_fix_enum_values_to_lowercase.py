"""fix_enum_values_to_lowercase

Revision ID: bfcc1d496b5d
Revises: f7467e162add
Create Date: 2025-07-17 02:48:31.329014

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'bfcc1d496b5d'
down_revision: Union[str, Sequence[str], None] = 'f7467e162add'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # 1. Create new enums with lowercase values
    op.execute("""
        CREATE TYPE bugbountyplatform_new AS ENUM ('hackerone', 'bugcrowd', 'intigriti', 'yeswehack', 'custom');
        CREATE TYPE targetscope_new AS ENUM ('domain', 'ip_range', 'subnet', 'wildcard');
        CREATE TYPE targetstatus_new AS ENUM ('active', 'inactive', 'archived', 'blacklisted');
    """)

    # 2. Alter columns to use new enums (with cast)
    op.execute("""
        ALTER TABLE public.targets ALTER COLUMN platform TYPE bugbountyplatform_new USING LOWER(platform::text)::bugbountyplatform_new;
        ALTER TABLE public.targets ALTER COLUMN scope TYPE targetscope_new USING LOWER(scope::text)::targetscope_new;
        ALTER TABLE public.targets ALTER COLUMN status TYPE targetstatus_new USING LOWER(status::text)::targetstatus_new;
    """)

    # 3. Drop old enums and rename new ones
    op.execute("""
        DROP TYPE bugbountyplatform;
        ALTER TYPE bugbountyplatform_new RENAME TO bugbountyplatform;
        DROP TYPE targetscope;
        ALTER TYPE targetscope_new RENAME TO targetscope;
        DROP TYPE targetstatus;
        ALTER TYPE targetstatus_new RENAME TO targetstatus;
    """)


def downgrade() -> None:
    """Downgrade schema."""
    # Downgrade logic (reverse the above if needed)
    pass
