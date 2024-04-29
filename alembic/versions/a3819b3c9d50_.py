"""empty message

Revision ID: a3819b3c9d50
Revises: 9d0d8756d0e3
Create Date: 2024-05-15 15:03:58.088880

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'a3819b3c9d50'
down_revision: Union[str, None] = '9d0d8756d0e3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###

    op.create_table('credential',
    sa.Column('id', sa.UUID(), autoincrement=False, nullable=False),
    sa.Column('organisationId', sa.UUID(), autoincrement=False, nullable=False),
    sa.Column('credentialExchangeId', sa.UUID(), autoincrement=False, nullable=False),
    sa.Column('credentialToken', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.Column('credential', postgresql.JSON(astext_type=sa.Text()), autoincrement=False, nullable=True),
    sa.Column('credentialStatus', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.Column('acceptanceToken', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.Column('deferredEndpoint', sa.VARCHAR(), autoincrement=False, nullable=True),
    sa.Column('createdAt', postgresql.TIMESTAMP(), autoincrement=False, nullable=True),
    sa.Column('updatedAt', postgresql.TIMESTAMP(), autoincrement=False, nullable=True),
    sa.ForeignKeyConstraint(['credentialExchangeId'], ['issue_credential_record.id'], name='credential_credentialExchangeId_fkey'),
    sa.ForeignKeyConstraint(['organisationId'], ['organisation.id'], name='credential_organisationId_fkey'),
    sa.PrimaryKeyConstraint('id', name='credential_pkey')
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('credential')
    # ### end Alembic commands ###