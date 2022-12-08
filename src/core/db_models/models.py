from datetime import datetime
from sqlalchemy import Column, Integer, String, func, DateTime, Boolean, ForeignKey
from config.db import Base


class TrackTimeMixin:
    created_on = Column(DateTime, server_default=func.now())
    updated_on = Column(DateTime, server_default=func.now(), onupdate=datetime.now())


class User(Base, TrackTimeMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    user_name = Column(String, unique=True, index=True)
    password = Column(String)
    verified = Column(Boolean, default=False)
    user_status = Column(Boolean, default=False)
    first_name = Column(String)
    last_name = Column(String)
    phone = Column(String)
    last_login_at = Column(DateTime, server_default=func.now())


class Role(Base, TrackTimeMixin):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    description = Column(String)


class UserRole(Base, TrackTimeMixin):
    __tablename__ = "user_roles"
    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("role.id"))
    user_id = Column(Integer, ForeignKey("user.id"))

