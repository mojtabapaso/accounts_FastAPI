from db.database import Base
from sqlalchemy import Column, Integer, Boolean, String


class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    phone_number = Column(String(11), unique=True, index=True)
    is_active = Column(Boolean, default=True)
    password = Column(String, nullable=True)
