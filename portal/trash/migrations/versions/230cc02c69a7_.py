"""empty message

Revision ID: 230cc02c69a7
Revises: c0410ac87519
Create Date: 2019-04-11 15:17:26.643099

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '230cc02c69a7'
down_revision = 'c0410ac87519'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('phone', sa.String(length=20), nullable=True))
    op.create_index(op.f('ix_users_phone'), 'users', ['phone'], unique=False)
    op.drop_index('ix_users_mobile_phone', table_name='users')
    op.drop_column('users', 'mobile_phone')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('users', sa.Column('mobile_phone', sa.VARCHAR(length=20), autoincrement=False, nullable=True))
    op.create_index('ix_users_mobile_phone', 'users', ['mobile_phone'], unique=False)
    op.drop_index(op.f('ix_users_phone'), table_name='users')
    op.drop_column('users', 'phone')
    # ### end Alembic commands ###