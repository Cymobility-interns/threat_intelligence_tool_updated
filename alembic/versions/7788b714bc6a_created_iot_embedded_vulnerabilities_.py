"""created iot_embedded_vulnerabilities table

Revision ID: 7788b714bc6a
Revises: fd200b5b0a7e
Create Date: 2026-02-12 15:20:52.890774

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7788b714bc6a'
down_revision: Union[str, Sequence[str], None] = 'fd200b5b0a7e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
