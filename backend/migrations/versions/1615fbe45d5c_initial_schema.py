"""initial schema

Revision ID: 1615fbe45d5c
Revises: 7a388a2b74a6
Create Date: 2025-07-28 17:38:31.452023

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1615fbe45d5c'
down_revision: Union[str, Sequence[str], None] = '7a388a2b74a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(op.f('active_recon_results_target_id_fkey'), 'active_recon_results', type_='foreignkey')
    op.create_foreign_key(None, 'active_recon_results', 'targets', ['target_id'], ['id'], source_schema='public', referent_schema='public')
    op.drop_constraint(op.f('attack_paths_kill_chain_id_fkey'), 'attack_paths', type_='foreignkey')
    op.create_foreign_key(None, 'attack_paths', 'kill_chains', ['kill_chain_id'], ['id'], source_schema='public', referent_schema='public')
    op.drop_constraint(op.f('kill_chains_target_id_fkey'), 'kill_chains', type_='foreignkey')
    op.create_foreign_key(None, 'kill_chains', 'targets', ['target_id'], ['id'], source_schema='public', referent_schema='public')
    op.drop_constraint(op.f('passive_recon_results_target_id_fkey'), 'passive_recon_results', type_='foreignkey')
    op.create_foreign_key(None, 'passive_recon_results', 'targets', ['target_id'], ['id'], source_schema='public', referent_schema='public')
    op.drop_constraint(op.f('ports_active_recon_result_id_fkey'), 'ports', type_='foreignkey')
    op.create_foreign_key(None, 'ports', 'active_recon_results', ['active_recon_result_id'], ['id'], source_schema='public', referent_schema='public')
    op.drop_constraint(op.f('reports_workflow_id_fkey'), 'reports', type_='foreignkey')
    op.drop_constraint(op.f('reports_target_id_fkey'), 'reports', type_='foreignkey')
    op.create_foreign_key(None, 'reports', 'targets', ['target_id'], ['id'], source_schema='public', referent_schema='public')
    op.create_foreign_key(None, 'reports', 'workflows', ['workflow_id'], ['id'], source_schema='public', referent_schema='public')
    op.drop_constraint(op.f('services_active_recon_result_id_fkey'), 'services', type_='foreignkey')
    op.drop_constraint(op.f('services_port_id_fkey'), 'services', type_='foreignkey')
    op.create_foreign_key(None, 'services', 'ports', ['port_id'], ['id'], source_schema='public', referent_schema='public')
    op.create_foreign_key(None, 'services', 'active_recon_results', ['active_recon_result_id'], ['id'], source_schema='public', referent_schema='public')
    op.drop_constraint(op.f('subdomains_passive_recon_result_id_fkey'), 'subdomains', type_='foreignkey')
    op.create_foreign_key(None, 'subdomains', 'passive_recon_results', ['passive_recon_result_id'], ['id'], source_schema='public', referent_schema='public')
    op.drop_constraint(op.f('vulnerabilities_target_id_fkey'), 'vulnerabilities', type_='foreignkey')
    op.create_foreign_key(None, 'vulnerabilities', 'targets', ['target_id'], ['id'], source_schema='public', referent_schema='public')
    op.drop_constraint(op.f('vulnerability_findings_vulnerability_id_fkey'), 'vulnerability_findings', type_='foreignkey')
    op.create_foreign_key(None, 'vulnerability_findings', 'vulnerabilities', ['vulnerability_id'], ['id'], source_schema='public', referent_schema='public')
    op.drop_constraint(op.f('workflow_executions_workflow_id_fkey'), 'workflow_executions', type_='foreignkey')
    op.create_foreign_key(None, 'workflow_executions', 'workflows', ['workflow_id'], ['id'], source_schema='public', referent_schema='public')
    op.drop_constraint(op.f('workflows_target_id_fkey'), 'workflows', type_='foreignkey')
    op.create_foreign_key(None, 'workflows', 'targets', ['target_id'], ['id'], source_schema='public', referent_schema='public')
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'workflows', schema='public', type_='foreignkey')
    op.create_foreign_key(op.f('workflows_target_id_fkey'), 'workflows', 'targets', ['target_id'], ['id'])
    op.drop_constraint(None, 'workflow_executions', schema='public', type_='foreignkey')
    op.create_foreign_key(op.f('workflow_executions_workflow_id_fkey'), 'workflow_executions', 'workflows', ['workflow_id'], ['id'])
    op.drop_constraint(None, 'vulnerability_findings', schema='public', type_='foreignkey')
    op.create_foreign_key(op.f('vulnerability_findings_vulnerability_id_fkey'), 'vulnerability_findings', 'vulnerabilities', ['vulnerability_id'], ['id'])
    op.drop_constraint(None, 'vulnerabilities', schema='public', type_='foreignkey')
    op.create_foreign_key(op.f('vulnerabilities_target_id_fkey'), 'vulnerabilities', 'targets', ['target_id'], ['id'])
    op.drop_constraint(None, 'subdomains', schema='public', type_='foreignkey')
    op.create_foreign_key(op.f('subdomains_passive_recon_result_id_fkey'), 'subdomains', 'passive_recon_results', ['passive_recon_result_id'], ['id'])
    op.drop_constraint(None, 'services', schema='public', type_='foreignkey')
    op.drop_constraint(None, 'services', schema='public', type_='foreignkey')
    op.create_foreign_key(op.f('services_port_id_fkey'), 'services', 'ports', ['port_id'], ['id'])
    op.create_foreign_key(op.f('services_active_recon_result_id_fkey'), 'services', 'active_recon_results', ['active_recon_result_id'], ['id'])
    op.drop_constraint(None, 'reports', schema='public', type_='foreignkey')
    op.drop_constraint(None, 'reports', schema='public', type_='foreignkey')
    op.create_foreign_key(op.f('reports_target_id_fkey'), 'reports', 'targets', ['target_id'], ['id'])
    op.create_foreign_key(op.f('reports_workflow_id_fkey'), 'reports', 'workflows', ['workflow_id'], ['id'])
    op.drop_constraint(None, 'ports', schema='public', type_='foreignkey')
    op.create_foreign_key(op.f('ports_active_recon_result_id_fkey'), 'ports', 'active_recon_results', ['active_recon_result_id'], ['id'])
    op.drop_constraint(None, 'passive_recon_results', schema='public', type_='foreignkey')
    op.create_foreign_key(op.f('passive_recon_results_target_id_fkey'), 'passive_recon_results', 'targets', ['target_id'], ['id'])
    op.drop_constraint(None, 'kill_chains', schema='public', type_='foreignkey')
    op.create_foreign_key(op.f('kill_chains_target_id_fkey'), 'kill_chains', 'targets', ['target_id'], ['id'])
    op.drop_constraint(None, 'attack_paths', schema='public', type_='foreignkey')
    op.create_foreign_key(op.f('attack_paths_kill_chain_id_fkey'), 'attack_paths', 'kill_chains', ['kill_chain_id'], ['id'])
    op.drop_constraint(None, 'active_recon_results', schema='public', type_='foreignkey')
    op.create_foreign_key(op.f('active_recon_results_target_id_fkey'), 'active_recon_results', 'targets', ['target_id'], ['id'])
    # ### end Alembic commands ###
