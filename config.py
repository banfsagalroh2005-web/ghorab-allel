"""إعدادات النظام — تُقرأ من متغيرات البيئة أو من ملف .env"""
import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_env_file():
    path = os.path.join(BASE_DIR, ".env")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_env_file()


def env(name, default=""):
    return os.environ.get(name, default).strip()


DATA_DIR = env("DATA_DIR") or os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)

# قاعدة البيانات المحلية (SQLite افتراضياً)
LOCAL_DATABASE_URL = env("LOCAL_DATABASE_URL") or "sqlite:///" + os.path.join(DATA_DIR, "local.db").replace("\\", "/")

# قاعدة البيانات على الإنترنت (PostgreSQL مثل Supabase / Neon / Render ...)
REMOTE_DATABASE_URL = env("REMOTE_DATABASE_URL") or env("DATABASE_URL")

# أي قاعدة يعمل عليها التطبيق مباشرة: local أو remote
DB_PRIMARY = env("DB_PRIMARY", "local").lower()
if not REMOTE_DATABASE_URL:
    DB_PRIMARY = "local"
if DB_PRIMARY not in ("local", "remote"):
    DB_PRIMARY = "local"

SYNC_INTERVAL = max(10, int(env("SYNC_INTERVAL", "30") or 30))
TIMEZONE = env("TIMEZONE", "Asia/Damascus")
TOKEN_HOURS = int(env("TOKEN_HOURS", "12") or 12)
HOST = env("HOST", "0.0.0.0")
PORT = int(env("PORT", "8000") or 8000)


def _secret():
    s = env("SECRET_KEY")
    if s:
        return s
    path = os.path.join(DATA_DIR, "secret.key")
    if os.path.exists(path):
        return open(path, encoding="utf-8").read().strip()
    s = secrets.token_hex(32)
    with open(path, "w", encoding="utf-8") as f:
        f.write(s)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return s


SECRET_KEY = _secret()

ADMIN_USERNAME = env("ADMIN_USERNAME", "admin").lower()
ADMIN_PASSWORD = env("ADMIN_PASSWORD")
SEED_DEMO = env("SEED_DEMO", "0") in ("1", "true", "yes")
