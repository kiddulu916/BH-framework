"""
Migration: Update workflowstatus and workflowstage enums to uppercase values
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '20240623_update_workflow_enums'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Rename old enums
    op.execute("ALTER TYPE workflowstatus RENAME TO workflowstatus_old;")
    op.execute("ALTER TYPE workflowstage RENAME TO workflowstage_old;")

    # Create new enums with uppercase values
    op.execute("""
        CREATE TYPE workflowstatus AS ENUM ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'PAUSED');
    """)
    op.execute("""
        CREATE TYPE workflowstage AS ENUM ('PASSIVE_RECON', 'ACTIVE_RECON', 'VULN_SCAN', 'VULN_TEST', 'KILL_CHAIN', 'REPORT');
    """)

    # Alter columns to use new enums, converting values to uppercase
    op.execute("""
        ALTER TABLE public.workflows ALTER COLUMN status TYPE workflowstatus USING UPPER(status::text)::workflowstatus;
    """)
    op.execute("""
        ALTER TABLE public.workflows ALTER COLUMN current_stage TYPE workflowstage USING UPPER(current_stage::text)::workflowstage;
    """)
    op.execute("""
        ALTER TABLE public.workflow_executions ALTER COLUMN stage TYPE workflowstage USING UPPER(stage::text)::workflowstage;
    """)
    op.execute("""
        ALTER TABLE public.workflow_executions ALTER COLUMN status TYPE workflowstatus USING UPPER(status::text)::workflowstatus;
    """)

    # Drop old enums
    op.execute("DROP TYPE workflowstatus_old;")
    op.execute("DROP TYPE workflowstage_old;")

def downgrade():
    # Not implemented (irreversible)
    pass 