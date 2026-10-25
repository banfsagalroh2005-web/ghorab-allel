"""نماذج قاعدة البيانات + محركات الاتصال (محلي / عبر الإنترنت)"""
import time
import uuid
import os
import sqlite3
from datetime import datetime

from sqlalchemy import (BigInteger, Boolean, Column, Float, Integer, String,
                        Text, create_engine, event, inspect, text)
from sqlalchemy.orm import declarative_base, sessionmaker

import config

Base = declarative_base()


def now_ms():
    return int(time.time() * 1000)


def new_id():
    return uuid.uuid4().hex


class SyncMixin:
    """كل جدول يحمل وقت آخر تعديل + علامة حذف ناعم ليمكن مزامنته بين القاعدتين"""
    updated_at = Column(BigInteger, nullable=False, default=now_ms, index=True)
    deleted = Column(Boolean, nullable=False, default=False)


class Department(SyncMixin, Base):
    __tablename__ = "departments"
    id = Column(String(32), primary_key=True, default=new_id)
    name = Column(String(100), nullable=False, index=True)
    manager = Column(String(100), default="غير محدد")


class Employee(SyncMixin, Base):
    __tablename__ = "employees"
    emp_no = Column(Integer, primary_key=True, autoincrement=False)
    name = Column(String(100), nullable=False)
    department = Column(String(100), nullable=False)
    job = Column(String(100), nullable=False)
    hire = Column(String(10), nullable=False)
    salary = Column(Float, nullable=False, default=0)
    status = Column(String(20), nullable=False, default="نشط")
    email = Column(String(150), default="")
    phone = Column(String(40), default="")


class User(SyncMixin, Base):
    __tablename__ = "users"
    id = Column(String(32), primary_key=True, default=new_id)
    username = Column(String(60), nullable=False, index=True)
    password_hash = Column(String(300), nullable=False)
    role = Column(String(20), nullable=False, default="employee")  # admin | employee
    emp_no = Column(Integer, nullable=True)
    active = Column(Boolean, nullable=False, default=True)
    must_change = Column(Boolean, nullable=False, default=False)


class Attendance(SyncMixin, Base):
    __tablename__ = "attendance"
    id = Column(String(40), primary_key=True)  # "<emp_no>:<date>"
    emp_no = Column(Integer, nullable=False, index=True)
    date = Column(String(10), nullable=False, index=True)
    in_time = Column(String(5), default="")
    out_time = Column(String(5), default="")
    status = Column(String(20), default="حاضر")


class Leave(SyncMixin, Base):
    __tablename__ = "leaves"
    id = Column(String(32), primary_key=True, default=new_id)
    emp_no = Column(Integer, nullable=False, index=True)
    type = Column(String(30), nullable=False)
    from_date = Column(String(10), nullable=False)
    to_date = Column(String(10), nullable=False)
    reason = Column(String(300), default="")
    status = Column(String(20), nullable=False, default="معلّق")
    decided_by = Column(String(60), default="")
    created_at = Column(BigInteger, default=now_ms)


class Activity(SyncMixin, Base):
    __tablename__ = "activities"
    id = Column(String(32), primary_key=True, default=new_id)
    text = Column(Text, nullable=False)
    user = Column(String(60), default="")
    ts = Column(BigInteger, default=now_ms, index=True)


class Setting(SyncMixin, Base):
    __tablename__ = "settings"
    key = Column(String(60), primary_key=True)
    value = Column(String(300), default="")


MODELS = [Department, Employee, User, Attendance, Leave, Activity, Setting]


def normalize_url(url):
    if url.startswith("postgres://"):
        return "postgresql+psycopg2://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        return "postgresql+psycopg2://" + url[len("postgresql://"):]
    return url


def make_engine(url):
    url = normalize_url(url)
    kw = {"pool_pre_ping": True}
    if url.startswith("sqlite"):
        kw["connect_args"] = {"check_same_thread": False, "timeout": 20}
    else:
        kw["connect_args"] = {"connect_timeout": 8}
        kw["pool_recycle"] = 1800
    eng = create_engine(url, **kw)
    if url.startswith("sqlite"):
        @event.listens_for(eng, "connect")
        def _pragmas(conn, _):
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.close()
    return eng


local_engine = make_engine(config.LOCAL_DATABASE_URL)
remote_engine = make_engine(config.REMOTE_DATABASE_URL) if config.REMOTE_DATABASE_URL else None

if config.DB_PRIMARY == "remote":
    primary_engine, secondary_engine = remote_engine, local_engine
else:
    primary_engine, secondary_engine = local_engine, remote_engine

PrimarySession = sessionmaker(bind=primary_engine, expire_on_commit=False)
SecondarySession = sessionmaker(bind=secondary_engine, expire_on_commit=False) if secondary_engine is not None else None


def _backup_sqlite_before_schema_change(engine):
    """Create a timestamped SQLite backup before adding sync metadata columns."""
    db_path = engine.url.database
    if not db_path or db_path == ":memory:" or not os.path.isfile(db_path):
        return None
    backup_path = db_path + ".before-sync-migration-" + datetime.now().strftime("%Y%m%d-%H%M%S") + ".bak"
    # SQLite's backup API creates a consistent copy even if WAL mode is enabled.
    with sqlite3.connect(db_path) as source, sqlite3.connect(backup_path) as target:
        source.backup(target)
    try:
        os.chmod(backup_path, 0o600)
    except OSError:
        pass
    return backup_path


def ensure_schema(engine):
    """Create missing tables and safely add sync columns to older app databases.

    SQLAlchemy's create_all() does not alter existing tables. Older SQLite copies
    may therefore lack updated_at/deleted, which are required for synchronization.
    Before touching such a database, save a timestamped backup and add only those
    two metadata columns; business data and existing columns are left untouched.
    """
    if engine is None:
        return

    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    needs_sync_migration = False
    for model in MODELS:
        table = model.__table__
        if table.name in existing_tables:
            present = {col["name"] for col in inspector.get_columns(table.name)}
            if any(c not in present for c in ("updated_at", "deleted")):
                needs_sync_migration = True
                break

    if needs_sync_migration and engine.dialect.name == "sqlite":
        backup_path = _backup_sqlite_before_schema_change(engine)
        if backup_path:
            print(f"نسخة احتياطية قبل تحديث مخطط قاعدة SQLite: {backup_path}", flush=True)

    Base.metadata.create_all(engine)

    # Add only the synchronization metadata columns to pre-existing tables.
    # Legacy rows are stamped as local changes so the selected primary database
    # is the source of truth on the first sync after this migration.
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())
    stamp_value = now_ms()
    with engine.begin() as conn:
        for model in MODELS:
            table = model.__table__
            if table.name not in existing_tables:
                continue
            present = {col["name"] for col in inspect(conn).get_columns(table.name)}
            if "updated_at" not in present:
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN updated_at BIGINT NOT NULL DEFAULT 0'))
                conn.execute(text(f'UPDATE "{table.name}" SET updated_at = :stamp WHERE updated_at = 0'), {"stamp": stamp_value})
            if "deleted" not in present:
                conn.execute(text(f'ALTER TABLE "{table.name}" ADD COLUMN deleted BOOLEAN NOT NULL DEFAULT 0'))


def kind_of(engine):
    if engine is None:
        return "—"
    return "SQLite محلية" if engine.dialect.name == "sqlite" else "PostgreSQL عبر الإنترنت" if engine.dialect.name == "postgresql" else engine.dialect.name


def stamp(obj):
    obj.updated_at = now_ms()
    return obj
