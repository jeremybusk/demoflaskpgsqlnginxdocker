"""empty message

Revision ID: 9d92a85fa0b5
Revises: 7e3605c36946
Create Date: 2019-05-10 11:27:32.708688

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9d92a85fa0b5'
down_revision = '7e3605c36946'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('prov_client',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=True),
    sa.Column('ips', sa.String(length=128), nullable=True),
    sa.Column('token', sa.String(length=128), nullable=True),
    sa.Column('note', sa.String(length=256), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('prov_client')
    # ### end Alembic commands ###
