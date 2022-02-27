from sqlalchemy import Column, String, Integer, ForeignKey, DateTime
from core.db import Base


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True, unique=True)
    username = Column(String, unique=True)
    password_hash = Column(String)


class Operations(Base):
    __tablename__ = 'operations'

    id = Column(Integer, primary_key=True, index=True, unique=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    transit_time = Column(DateTime)
