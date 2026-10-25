"""المزامنة ثنائية الاتجاه بين القاعدة المحلية وقاعدة الإنترنت (آخر تعديل يفوز)"""
import threading
import time

from sqlalchemy import inspect as sa_inspect
from sqlalchemy.exc import IntegrityError

import config
import database as D

STATE = {
    "enabled": D.secondary_engine is not None,
    "running": False,
    "last_run": None,
    "last_ok": None,
    "last_error": None,
    "pushed": 0,
    "pulled": 0,
    "conflicts": 0,
}
_lock = threading.Lock()
_wake = threading.Event()
_started = False


def _clean_error(e):
    msg = str(e)
    for url in (config.REMOTE_DATABASE_URL, config.LOCAL_DATABASE_URL):
        if url:
            msg = msg.replace(url, "***")
    # إخفاء أي كلمة مرور داخل رابط اتصال
    import re
    msg = re.sub(r"://([^:/@\s]+):([^@\s]+)@", r"://\1:***@", msg)
    return msg.splitlines()[0][:300] if msg else e.__class__.__name__


def _pk(M):
    return sa_inspect(M).primary_key[0]


def _copy(M, src, dst, keys):
    cols = [c.name for c in M.__table__.columns]
    pk = _pk(M)
    n = 0
    for i in range(0, len(keys), 300):
        chunk = keys[i:i + 300]
        rows = src.query(M).filter(pk.in_(chunk)).all()
        datas = [{c: getattr(r, c) for c in cols} for r in rows]
        try:
            for d in datas:
                dst.merge(M(**d))
            dst.commit()
            n += len(datas)
        except IntegrityError:
            dst.rollback()
            for d in datas:
                try:
                    dst.merge(M(**d))
                    dst.commit()
                    n += 1
                except IntegrityError:
                    dst.rollback()
                    STATE["conflicts"] += 1
    return n


def run_sync():
    """يشغّل مزامنة كاملة. آمن للاستدعاء من عدة أماكن."""
    if D.secondary_engine is None:
        return STATE
    if not _lock.acquire(blocking=False):
        return STATE
    STATE["running"] = True
    STATE["last_run"] = D.now_ms()
    pushed = pulled = 0
    try:
        D.ensure_schema(D.primary_engine)
        D.ensure_schema(D.secondary_engine)
        STATE["conflicts"] = 0
        for M in D.MODELS:
            pk = _pk(M)
            with D.PrimarySession() as a, D.SecondarySession() as b:
                ma = {k: t for k, t in a.query(pk, M.updated_at).all()}
                mb = {k: t for k, t in b.query(pk, M.updated_at).all()}
                to_b = [k for k, t in ma.items() if k not in mb or t > mb[k]]
                to_a = [k for k, t in mb.items() if k not in ma or t > ma[k]]
                if to_b:
                    pushed += _copy(M, a, b, to_b)
                if to_a:
                    pulled += _copy(M, b, a, to_a)
        STATE.update(pushed=pushed, pulled=pulled, last_ok=D.now_ms(), last_error=None)
    except Exception as e:  # noqa
        STATE["last_error"] = _clean_error(e)
    finally:
        STATE["running"] = False
        _lock.release()
    return STATE


def request_sync():
    """يُستدعى بعد كل تعديل لدفع التغييرات للقاعدة الأخرى خلال ثوانٍ"""
    if D.secondary_engine is not None:
        _wake.set()


def _loop():
    while True:
        _wake.wait(timeout=config.SYNC_INTERVAL)
        if _wake.is_set():
            time.sleep(1.5)  # تجميع عدة تعديلات متتالية
            _wake.clear()
        run_sync()


def start_background():
    global _started
    if _started or D.secondary_engine is None:
        return
    _started = True
    threading.Thread(target=_loop, daemon=True, name="db-sync").start()


def status():
    s = dict(STATE)
    s.update(
        primary=D.kind_of(D.primary_engine),
        secondary=D.kind_of(D.secondary_engine) if D.secondary_engine is not None else None,
        primary_role="remote" if config.DB_PRIMARY == "remote" else "local",
        interval=config.SYNC_INTERVAL,
    )
    return s
