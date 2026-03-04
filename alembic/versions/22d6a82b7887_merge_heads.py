"""merge heads

Revision ID: 22d6a82b7887
Revises: 739b109f726a, 7788b714bc6a
Create Date: 2026-03-04 14:35:24.550462

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '22d6a82b7887'
down_revision: Union[str, Sequence[str], None] = ('739b109f726a', '7788b714bc6a')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
