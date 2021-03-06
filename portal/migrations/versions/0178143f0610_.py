"""empty message

Revision ID: 0178143f0610
Revises: 8518af7f234f
Create Date: 2019-05-06 20:46:56.038138

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0178143f0610'
down_revision = '8518af7f234f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('key', sa.Column('private_key', sa.String(), nullable=True))
    op.add_column('key', sa.Column('public_key', sa.String(), nullable=True))
    op.drop_column('key', 'private_keys')
    op.drop_column('key', 'public_keys')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('key', sa.Column('public_keys', sa.VARCHAR(), autoincrement=False, nullable=True))
    op.add_column('key', sa.Column('private_keys', sa.VARCHAR(), autoincrement=False, nullable=True))
    op.drop_column('key', 'public_key')
    op.drop_column('key', 'private_key')
    # ### end Alembic commands ###
