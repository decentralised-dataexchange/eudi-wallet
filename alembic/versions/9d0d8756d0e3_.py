"""empty message

Revision ID: 9d0d8756d0e3
Revises: 3be60cbb77ee
Create Date: 2024-05-09 11:51:16.326563

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9d0d8756d0e3'
down_revision: Union[str, None] = '3be60cbb77ee'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('organisation', sa.Column('cryptographic_salt', sa.String(length=500), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('organisation', 'cryptographic_salt')
    # ### end Alembic commands ###
