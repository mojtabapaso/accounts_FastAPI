from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from setting import DATABASE_URL
# SQLALCHEMY_DATABASE_URL = 'postgresql://fast:fast@localhost:5432/testapi'
# engine = create_engine(DATABASE_URL)

engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()
metadata = MetaData()
database = Base()
