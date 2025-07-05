"""fix_enum_values_to_lowercase

Revision ID: 895123be9654
Revises: efb4327bc31d
Create Date: 2025-07-02 17:10:06.179350

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '895123be9654'
down_revision: Union[str, Sequence[str], None] = 'efb4327bc31d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema - convert enum values to lowercase to match Python model."""
    
    # 1. Rename the old enum types
    op.execute("ALTER TYPE reportstatus RENAME TO reportstatus_old")
    op.execute("ALTER TYPE reportformat RENAME TO reportformat_old")
    op.execute("ALTER TYPE reporttype RENAME TO reporttype_old")
    
    # 2. Create new enum types with lowercase values
    op.execute("CREATE TYPE reportstatus AS ENUM ('generating', 'completed', 'failed', 'cancelled')")
    op.execute("CREATE TYPE reportformat AS ENUM ('pdf', 'html', 'markdown', 'json', 'xml')")
    op.execute("CREATE TYPE reporttype AS ENUM ('executive_summary', 'technical_detailed', 'vulnerability_report', 'kill_chain_analysis', 'compliance_report', 'custom')")
    
    # 3. Alter columns to use text temporarily
    op.execute("ALTER TABLE reports ALTER COLUMN status DROP DEFAULT")
    op.execute("ALTER TABLE reports ALTER COLUMN status TYPE text USING status::text")
    op.execute("ALTER TABLE reports ALTER COLUMN format DROP DEFAULT")
    op.execute("ALTER TABLE reports ALTER COLUMN format TYPE text USING format::text")
    op.execute("ALTER TABLE reports ALTER COLUMN report_type DROP DEFAULT")
    op.execute("ALTER TABLE reports ALTER COLUMN report_type TYPE text USING report_type::text")
    
    # 4. Update all values to lowercase
    op.execute("UPDATE reports SET status = LOWER(status)")
    op.execute("UPDATE reports SET format = LOWER(format)")
    op.execute("UPDATE reports SET report_type = LOWER(report_type)")
    
    # 5. Alter columns to use the new enum types
    op.execute("ALTER TABLE reports ALTER COLUMN status TYPE reportstatus USING status::reportstatus")
    op.execute("ALTER TABLE reports ALTER COLUMN format TYPE reportformat USING format::reportformat")
    op.execute("ALTER TABLE reports ALTER COLUMN report_type TYPE reporttype USING report_type::reporttype")
    
    # 6. Set defaults again
    op.execute("ALTER TABLE reports ALTER COLUMN status SET DEFAULT 'generating'")
    op.execute("ALTER TABLE reports ALTER COLUMN format SET DEFAULT 'pdf'")
    op.execute("ALTER TABLE reports ALTER COLUMN report_type SET DEFAULT 'technical_detailed'")
    
    # 7. Drop the old enum types
    op.execute("DROP TYPE reportstatus_old")
    op.execute("DROP TYPE reportformat_old")
    op.execute("DROP TYPE reporttype_old")


def downgrade() -> None:
    """Downgrade schema - convert enum values back to uppercase."""
    
    # 1. Rename the new enum types
    op.execute("ALTER TYPE reportstatus RENAME TO reportstatus_new")
    op.execute("ALTER TYPE reportformat RENAME TO reportformat_new")
    op.execute("ALTER TYPE reporttype RENAME TO reporttype_new")
    
    # 2. Create old enum types with uppercase values
    op.execute("CREATE TYPE reportstatus AS ENUM ('GENERATING', 'COMPLETED', 'FAILED', 'CANCELLED')")
    op.execute("CREATE TYPE reportformat AS ENUM ('PDF', 'HTML', 'MARKDOWN', 'JSON', 'XML')")
    op.execute("CREATE TYPE reporttype AS ENUM ('EXECUTIVE_SUMMARY', 'TECHNICAL_DETAILED', 'VULNERABILITY_REPORT', 'KILL_CHAIN_ANALYSIS', 'COMPLIANCE_REPORT', 'CUSTOM')")
    
    # 3. Alter columns to use text temporarily
    op.execute("ALTER TABLE reports ALTER COLUMN status DROP DEFAULT")
    op.execute("ALTER TABLE reports ALTER COLUMN status TYPE text USING status::text")
    op.execute("ALTER TABLE reports ALTER COLUMN format DROP DEFAULT")
    op.execute("ALTER TABLE reports ALTER COLUMN format TYPE text USING format::text")
    op.execute("ALTER TABLE reports ALTER COLUMN report_type DROP DEFAULT")
    op.execute("ALTER TABLE reports ALTER COLUMN report_type TYPE text USING report_type::text")
    
    # 4. Update all values to uppercase
    op.execute("UPDATE reports SET status = UPPER(status)")
    op.execute("UPDATE reports SET format = UPPER(format)")
    op.execute("UPDATE reports SET report_type = UPPER(report_type)")
    
    # 5. Alter columns to use the old enum types
    op.execute("ALTER TABLE reports ALTER COLUMN status TYPE reportstatus USING status::reportstatus")
    op.execute("ALTER TABLE reports ALTER COLUMN format TYPE reportformat USING format::reportformat")
    op.execute("ALTER TABLE reports ALTER COLUMN report_type TYPE reporttype USING report_type::reporttype")
    
    # 6. Set defaults again
    op.execute("ALTER TABLE reports ALTER COLUMN status SET DEFAULT 'GENERATING'")
    op.execute("ALTER TABLE reports ALTER COLUMN format SET DEFAULT 'PDF'")
    op.execute("ALTER TABLE reports ALTER COLUMN report_type SET DEFAULT 'TECHNICAL_DETAILED'")
    
    # 7. Drop the new enum types
    op.execute("DROP TYPE reportstatus_new")
    op.execute("DROP TYPE reportformat_new")
    op.execute("DROP TYPE reporttype_new")
