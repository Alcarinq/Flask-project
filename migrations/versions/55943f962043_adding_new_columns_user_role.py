"""adding_new_columns_user_role

Revision ID: 55943f962043
Revises: fb3f44f459b7
Create Date: 2021-08-10 14:13:09.561679

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '55943f962043'
down_revision = 'fb3f44f459b7'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('roles', sa.Column('default', sa.Boolean(), nullable=True))
    op.add_column('roles', sa.Column('permissions', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_roles_default'), 'roles', ['default'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_roles_default'), table_name='roles')
    op.drop_column('roles', 'permissions')
    op.drop_column('roles', 'default')
    # ### end Alembic commands ###
