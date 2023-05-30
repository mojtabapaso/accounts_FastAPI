"""Added User Profile OtoCode table

Revision ID: 46bc7e4e5415
Revises: 
Create Date: 2023-05-23 15:02:14.677760

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '46bc7e4e5415'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('otp_code',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('code', sa.String(length=7), nullable=True),
    sa.Column('expired', sa.Boolean(), nullable=True),
    sa.Column('phone_number', sa.String(length=11), nullable=True),
    sa.Column('time', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_otp_code_code'), 'otp_code', ['code'], unique=False)
    op.create_index(op.f('ix_otp_code_id'), 'otp_code', ['id'], unique=False)
    op.create_index(op.f('ix_otp_code_phone_number'), 'otp_code', ['phone_number'], unique=False)
    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('phone_number', sa.String(length=11), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.Column('password', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    op.create_index(op.f('ix_users_phone_number'), 'users', ['phone_number'], unique=True)
    op.create_table('profile',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('email', sa.String(), nullable=True),
    sa.Column('first_name', sa.String(), nullable=True),
    sa.Column('last_name', sa.String(), nullable=True),
    sa.Column('phone_number', sa.String(length=11), nullable=True),
    sa.ForeignKeyConstraint(['phone_number'], ['users.phone_number'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_index(op.f('ix_profile_id'), 'profile', ['id'], unique=False)
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_profile_id'), table_name='profile')
    op.drop_table('profile')
    op.drop_index(op.f('ix_users_phone_number'), table_name='users')
    op.drop_index(op.f('ix_users_id'), table_name='users')
    op.drop_table('users')
    op.drop_index(op.f('ix_otp_code_phone_number'), table_name='otp_code')
    op.drop_index(op.f('ix_otp_code_id'), table_name='otp_code')
    op.drop_index(op.f('ix_otp_code_code'), table_name='otp_code')
    op.drop_table('otp_code')
    # ### end Alembic commands ###
