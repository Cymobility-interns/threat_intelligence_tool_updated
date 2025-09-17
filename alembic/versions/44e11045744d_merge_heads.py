"""merge heads

Revision ID: 44e11045744d
Revises: 799f9fedb3cc, 98445eced13d
Create Date: 2025-08-25 13:19:55.830549

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '44e11045744d'
down_revision: Union[str, Sequence[str], None] = ('799f9fedb3cc', '98445eced13d')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
