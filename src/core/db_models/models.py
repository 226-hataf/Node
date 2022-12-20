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


class Group(Base, TrackTimeMixin):
    __tablename__ = "groups"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    description = Column(String)


class GroupsRole(Base, TrackTimeMixin):
    __tablename__ = "groups_roles"
    id = Column(Integer, primary_key=True, index=True)
    roles_id = Column(Integer, ForeignKey("roles.id"))
    groups_id = Column(Integer, ForeignKey("groups.id"))


class GroupsUser(Base, TrackTimeMixin):
    __tablename__ = "groups_users"
    id = Column(Integer, primary_key=True, index=True)
    groups_id = Column(Integer, ForeignKey("groups.id"))
    users_id = Column(Integer, ForeignKey("users.id"))
