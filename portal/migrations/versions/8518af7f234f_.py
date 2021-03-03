"""empty message

Revision ID: 8518af7f234f
Revises: d4849e54eec3
Create Date: 2019-05-06 20:46:17.773594

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8518af7f234f'
down_revision = 'd4849e54eec3'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('key', sa.Column('private_keys', sa.String(), nullable=True))
    op.add_column('key', sa.Column('public_keys', sa.String(), nullable=True))
    op.drop_column('key', 'public_key')
    op.drop_column('key', 'private_key')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('key', sa.Column('private_key', sa.VARCHAR(length=1024), autoincrement=False, nullable=True))
    op.add_column('key', sa.Column('public_key', sa.VARCHAR(length=512), autoincrement=False, nullable=True))
    op.drop_column('key', 'public_keys')
    op.drop_column('key', 'private_keys')
    # ### end Alembic commands ###
