from sqlalchemy.orm import relationship
from db.database import Base
from sqlalchemy import Column, Integer, String, ForeignKey


class Profile(Base):
    __tablename__ = 'profile'
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    phone_number = Column(String(11), ForeignKey('users.phone_number'))
    user = relationship("User", backref="profiles")