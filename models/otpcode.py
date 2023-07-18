from db.database import Base
from sqlalchemy import Column, Integer, Boolean, DateTime, String
from datetime import datetime


class OtpCode(Base):
    __tablename__ = 'otp_code'
    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(7), index=True)
    expired = Column(Boolean, default=True)
    phone_number = Column(String(11), index=True)
    time = Column(DateTime, default=datetime.now)
