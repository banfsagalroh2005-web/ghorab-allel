"""غراب الليل — نظام إدارة الموظفين (Flask + SQLAlchemy)"""
import functools
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import jwt
from flask import Flask, g, jsonify, request, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash

import config
import database as D
import sync
from database import (Activity, Attendance, Department, Employee, Leave,
                      Setting, User, stamp)

app = Flask(__name__, static_folder="static", static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024
TZ = ZoneInfo(config.TIMEZONE)

DEFAULT_SETTINGS = {
    "org": "غراب الليل", "currency": "ل.س", "work_start": "09:00",
    "grace_min": "15", "allowance_pct": "10", "deduction_pct": "2",
}
LEAVE_TYPES = ["سنوية", "مرضية", "طارئة", "بدون راتب"]
EMP_STATUS = ["نشط", "موقوف"]
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
USER_RE = re.compile(r"^[a-z0-9_.@-]{3,40}$")
MAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ───────────────────────── أدوات عامة ─────────────────────────
class ApiError(Exception):
    def __init__(self, msg, code=400):
        self.msg, self.code = msg, code


@app.errorhandler(ApiError)
def _api_error(e):
    return jsonify(error=e.msg), e.code


@app.errorhandler(404)
def _nf(e):
    if request.path.startswith("/api/"):
        return jsonify(error="غير موجود"), 404
    return send_from_directory(app.static_folder, "index.html")


@app.errorhandler(405)
def _mna(e):
    return jsonify(error="طريقة غير مسموحة"), 405


@app.errorhandler(Exception)
def _any(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        return jsonify(error=e.description), e.code
    app.logger.exception("خطأ غير متوقع")
    return jsonify(error="حدث خطأ في الخادم"), 500


def db():
    if "db" not in g:
        g.db = D.PrimarySession()
    return g.db


@app.teardown_appcontext
def _close(_):
    s = g.pop("db", None)
    if s is not None:
        s.close()


def commit():
    db().commit()
    sync.request_sync()


def now_local():
    return datetime.now(TZ)


def today_str():
    return now_local().strftime("%Y-%m-%d")


def body():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError("بيانات غير صالحة")
    return data


def s_(v, name, maxlen=100, required=True):
    v = "" if v is None else str(v).strip()
    if required and not v:
        raise ApiError(f"الحقل «{name}» مطلوب")
    if len(v) > maxlen:
        raise ApiError(f"الحقل «{name}» أطول من المسموح")
    return v


def date_(v, name):
    v = s_(v, name, 10)
    try:
        datetime.strptime(v, "%Y-%m-%d")
    except ValueError:
        raise ApiError(f"تاريخ غير صالح في «{name}»")
    return v


def time_(v, name):
    v = s_(v, name, 5)
    if not TIME_RE.match(v):
        raise ApiError(f"وقت غير صالح في «{name}»")
    return v


def num_(v, name, lo=0, hi=1e12):
    try:
        n = float(v)
    except (TypeError, ValueError):
        raise ApiError(f"قيمة غير صالحة في «{name}»")
    if n != n or n < lo or n > hi:
        raise ApiError(f"قيمة خارج المسموح في «{name}»")
    return n


def check_password(p):
    if not isinstance(p, str) or len(p) < 8:
        raise ApiError("كلمة المرور يجب ألا تقل عن 8 أحرف")
    if len(p) > 100:
        raise ApiError("كلمة المرور طويلة جداً")
    return p


def hash_pw(p):
    return generate_password_hash(p, method="pbkdf2:sha256:600000")


def log(text):
    u = getattr(g, "user", None)
    db().add(Activity(text=text[:300], user=u.username if u else ""))


# ───────────────────────── الإعدادات ─────────────────────────
def get_settings():
    out = dict(DEFAULT_SETTINGS)
    for r in db().query(Setting).filter_by(deleted=False).all():
        out[r.key] = r.value
    return out


def calc_status(in_time, st):
    h, m = map(int, st["work_start"].split(":"))
    limit = h * 60 + m + int(float(st["grace_min"]))
    ih, im = map(int, in_time.split(":"))
    return "متأخر" if ih * 60 + im > limit else "حاضر"


# ───────────────────────── المصادقة ─────────────────────────
_fails = {}


def _rate_key(username):
    return f"{request.remote_addr}|{username}"


def _is_blocked(key):
    now = time.time()
    lst = [t for t in _fails.get(key, []) if now - t < 300]
    _fails[key] = lst
    return len(lst) >= 6


def make_token(u):
    exp = datetime.now(timezone.utc) + timedelta(hours=config.TOKEN_HOURS)
    return jwt.encode({"uid": u.id, "exp": exp}, config.SECRET_KEY, algorithm="HS256")


def current_user():
    h = request.headers.get("Authorization", "")
    if not h.startswith("Bearer "):
        return None
    try:
        p = jwt.decode(h[7:], config.SECRET_KEY, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    u = db().get(User, p.get("uid"))
    if not u or u.deleted or not u.active:
        return None
    return u


def require(role=None):
    def deco(fn):
        @functools.wraps(fn)
        def w(*a, **k):
            u = current_user()
            if not u:
                raise ApiError("انتهت الجلسة، سجّل الدخول من جديد", 401)
            if role and u.role != role:
                raise ApiError("ليست لديك صلاحية لهذا الإجراء", 403)
            g.user = u
            return fn(*a, **k)
        return w
    return deco


def user_out(u):
    emp = db().get(Employee, u.emp_no) if u.emp_no is not None else None
    return {"id": u.id, "username": u.username, "role": u.role, "emp_no": u.emp_no,
            "name": emp.name if emp and not emp.deleted else u.username,
            "active": u.active, "must_change": u.must_change}


@app.post("/api/login")
def login():
    d = body()
    username = s_(d.get("username"), "اسم المستخدم", 60).lower()
    password = str(d.get("password") or "")
    key = _rate_key(username)
    if _is_blocked(key):
        raise ApiError("محاولات كثيرة. انتظر 5 دقائق ثم حاول مجدداً", 429)
    u = db().query(User).filter_by(username=username, deleted=False).first()
    ok = check_password_hash(u.password_hash if u else _DUMMY, password) and u is not None
    if not (u and ok and u.active):
        _fails.setdefault(key, []).append(time.time())
        raise ApiError("اسم المستخدم أو كلمة المرور غير صحيحة", 401)
    _fails.pop(key, None)
    g.user = u
    log(f"تسجيل دخول: {u.username}")
    commit()
    return jsonify(token=make_token(u), user=user_out(u))


_DUMMY = generate_password_hash("dummy-password", method="pbkdf2:sha256:600000")


@app.get("/api/me")
@require()
def me():
    return jsonify(user=user_out(g.user))


@app.post("/api/me/password")
@require()
def change_password():
    d = body()
    if not check_password_hash(g.user.password_hash, str(d.get("old") or "")):
        raise ApiError("كلمة المرور الحالية غير صحيحة", 400)
    new = check_password(d.get("new"))
    if new == d.get("old"):
        raise ApiError("اختر كلمة مرور مختلفة عن الحالية")
    g.user.password_hash = hash_pw(new)
    g.user.must_change = False
    stamp(g.user)
    log(f"تغيير كلمة المرور: {g.user.username}")
    commit()
    return jsonify(ok=True)


# ───────────────────────── تحويل البيانات ─────────────────────────
def emp_out(e, accounts=None):
    return {"emp_no": e.emp_no, "name": e.name, "department": e.department, "job": e.job,
            "hire": e.hire, "salary": e.salary, "status": e.status, "email": e.email or "",
            "phone": e.phone or "", "has_account": (e.emp_no in accounts) if accounts is not None else None}


def names_map():
    return {e.emp_no: (e.name + (" (محذوف)" if e.deleted else "")) for e in db().query(Employee).all()}


def leave_out(l, names):
    return {"id": l.id, "emp_no": l.emp_no, "name": names.get(l.emp_no, "—"), "type": l.type,
            "from": l.from_date, "to": l.to_date, "reason": l.reason or "", "status": l.status,
            "decided_by": l.decided_by or "", "created_at": l.created_at}


def att_out(a, names):
    return {"id": a.id, "emp_no": a.emp_no, "name": names.get(a.emp_no, "—"), "date": a.date,
            "in": a.in_time or "", "out": a.out_time or "", "status": a.status}


def payslip(e, st):
    allowance = round(e.salary * float(st["allowance_pct"]) / 100)
    deduction = round(e.salary * float(st["deduction_pct"]) / 100)
    return {"emp_no": e.emp_no, "name": e.name, "department": e.department, "salary": e.salary,
            "allowance": allowance, "deduction": deduction, "net": e.salary + allowance - deduction}


def accounts_set():
    return {u.emp_no for u in db().query(User).filter_by(deleted=False).all() if u.emp_no is not None}


def today_summary():
    s, t = db(), today_str()
    active = [e for e in s.query(Employee).filter_by(deleted=False, status="نشط").all()]
    present = {a.emp_no for a in s.query(Attendance).filter_by(date=t, deleted=False).all() if a.in_time}
    on_leave = {l.emp_no for l in s.query(Leave).filter_by(deleted=False, status="مقبول").all()
                if l.from_date <= t <= l.to_date}
    recs = s.query(Attendance).filter_by(date=t, deleted=False).count()
    absent = len([e for e in active if e.emp_no not in present and e.emp_no not in on_leave])
    return {"date": t, "present": len(present), "absent": absent, "on_leave": len(on_leave), "records": recs}


# ───────────────────────── تحميل أولي ─────────────────────────
@app.get("/api/bootstrap")
@require()
def bootstrap():
    s, u = db(), g.user
    st = get_settings()
    names = names_map()
    if u.role == "admin":
        accounts = accounts_set()
        emps = s.query(Employee).filter_by(deleted=False).order_by(Employee.emp_no.desc()).all()
        deps = s.query(Department).filter_by(deleted=False).order_by(Department.name).all()
        leaves = s.query(Leave).filter_by(deleted=False).order_by(Leave.created_at.desc()).limit(300).all()
        acts = s.query(Activity).filter_by(deleted=False).order_by(Activity.ts.desc()).limit(8).all()
        return jsonify(
            user=user_out(u), settings=st,
            employees=[emp_out(e, accounts) for e in emps],
            departments=[{"id": d.id, "name": d.name, "manager": d.manager} for d in deps],
            leaves=[leave_out(l, names) for l in leaves],
            activities=[{"text": a.text, "user": a.user, "ts": a.ts} for a in acts],
            today=today_summary())
    # موظف: بياناته فقط
    emp = s.get(Employee, u.emp_no) if u.emp_no is not None else None
    if emp and emp.deleted:
        emp = None
    leaves = []
    today_row, month = None, {"present": 0, "late": 0}
    if emp:
        leaves = s.query(Leave).filter_by(emp_no=emp.emp_no, deleted=False).order_by(Leave.created_at.desc()).limit(100).all()
        row = s.get(Attendance, f"{emp.emp_no}:{today_str()}")
        today_row = att_out(row, names) if row and not row.deleted else None
        prefix = today_str()[:7]
        rows = s.query(Attendance).filter(Attendance.emp_no == emp.emp_no, Attendance.deleted == False,  # noqa
                                           Attendance.date.like(prefix + "%")).all()
        month = {"present": len([r for r in rows if r.in_time]), "late": len([r for r in rows if r.status == "متأخر"])}
    return jsonify(
        user=user_out(u), settings={k: st[k] for k in ("org", "currency", "work_start", "grace_min")},
        employee=emp_out(emp) if emp else None,
        leaves=[leave_out(l, names) for l in leaves],
        today_row=today_row, month=month, today={"date": today_str()})


# ───────────────────────── الموظفون ─────────────────────────
def validate_employee(d, partial_dept_check=True):
    name = s_(d.get("name"), "الاسم", 100)
    dept = s_(d.get("department"), "القسم", 100)
    if not db().query(Department).filter_by(name=dept, deleted=False).first():
        raise ApiError("القسم غير موجود")
    status = s_(d.get("status") or "نشط", "الحالة", 20)
    if status not in EMP_STATUS:
        raise ApiError("حالة غير صالحة")
    email = s_(d.get("email"), "البريد", 150, required=False)
    if email and not MAIL_RE.match(email):
        raise ApiError("البريد الإلكتروني غير صالح")
    return dict(name=name, department=dept, job=s_(d.get("job"), "المسمى الوظيفي", 100),
                hire=date_(d.get("hire"), "تاريخ التعيين"), salary=num_(d.get("salary"), "الراتب"),
                status=status, email=email, phone=s_(d.get("phone"), "الهاتف", 40, required=False))


def create_user(username, password, role, emp_no=None):
    username = s_(username, "اسم المستخدم", 40).lower()
    if not USER_RE.match(username):
        raise ApiError("اسم المستخدم: 3-40 حرفاً إنجليزياً/أرقاماً أو . _ - @")
    check_password(password)
    if db().query(User).filter_by(username=username, deleted=False).first():
        raise ApiError("اسم المستخدم مستخدم مسبقاً")
    if emp_no is not None and db().query(User).filter_by(emp_no=emp_no, deleted=False).first():
        raise ApiError("لهذا الموظف حساب مسبقاً")
    u = User(username=username, password_hash=hash_pw(password), role=role, emp_no=emp_no,
             active=True, must_change=True)
    db().add(u)
    return u


@app.post("/api/employees")
@require("admin")
def add_employee():
    d = body()
    vals = validate_employee(d)
    if d.get("emp_no") in (None, ""):
        mx = db().query(Employee.emp_no).order_by(Employee.emp_no.desc()).first()
        emp_no = max(1000, mx[0] if mx else 1000) + 1
    else:
        emp_no = int(num_(d.get("emp_no"), "الرقم الوظيفي", 1, 10**9))
    if db().get(Employee, emp_no):
        raise ApiError("الرقم الوظيفي مستخدم مسبقاً", 409)
    e = Employee(emp_no=emp_no, **vals)
    db().add(e)
    if d.get("username"):
        create_user(d.get("username"), d.get("password"), "employee", emp_no)
    log("تمت إضافة الموظف " + e.name)
    commit()
    return jsonify(employee=emp_out(e)), 201


@app.put("/api/employees/<int:emp_no>")
@require("admin")
def edit_employee(emp_no):
    e = db().get(Employee, emp_no)
    if not e or e.deleted:
        raise ApiError("الموظف غير موجود", 404)
    for k, v in validate_employee(body()).items():
        setattr(e, k, v)
    stamp(e)
    log("تم تعديل بيانات " + e.name)
    commit()
    return jsonify(employee=emp_out(e))


@app.delete("/api/employees/<int:emp_no>")
@require("admin")
def del_employee(emp_no):
    e = db().get(Employee, emp_no)
    if not e or e.deleted:
        raise ApiError("الموظف غير موجود", 404)
    if g.user.emp_no == emp_no:
        raise ApiError("لا يمكنك حذف موظفك المرتبط بحسابك الحالي")
    e.deleted = True
    stamp(e)
    for u in db().query(User).filter_by(emp_no=emp_no, deleted=False).all():
        u.deleted, u.active = True, False
        stamp(u)
    log("تم حذف الموظف " + e.name)
    commit()
    return jsonify(ok=True)


# ───────────────────────── الأقسام ─────────────────────────
@app.post("/api/departments")
@require("admin")
def add_department():
    d = body()
    name = s_(d.get("name"), "اسم القسم", 100)
    if db().query(Department).filter_by(name=name, deleted=False).first():
        raise ApiError("هذا القسم موجود مسبقاً", 409)
    dep = Department(name=name, manager=s_(d.get("manager") or "غير محدد", "المدير", 100))
    db().add(dep)
    log("تمت إضافة قسم " + name)
    commit()
    return jsonify(ok=True), 201


@app.delete("/api/departments/<did>")
@require("admin")
def del_department(did):
    dep = db().get(Department, did)
    if not dep or dep.deleted:
        raise ApiError("القسم غير موجود", 404)
    if db().query(Employee).filter_by(department=dep.name, deleted=False).count():
        raise ApiError("لا يمكن حذف قسم يحتوي على موظفين")
    dep.deleted = True
    stamp(dep)
    log("تم حذف قسم " + dep.name)
    commit()
    return jsonify(ok=True)


# ───────────────────────── الحضور ─────────────────────────
@app.get("/api/attendance")
@require()
def list_attendance():
    t = today_str()
    frm = date_(request.args.get("from") or (now_local() - timedelta(days=6)).strftime("%Y-%m-%d"), "من")
    to = date_(request.args.get("to") or t, "إلى")
    q = db().query(Attendance).filter(Attendance.deleted == False, Attendance.date >= frm, Attendance.date <= to)  # noqa
    if g.user.role != "admin":
        if g.user.emp_no is None:
            return jsonify(rows=[])
        q = q.filter(Attendance.emp_no == g.user.emp_no)
    elif request.args.get("emp_no"):
        q = q.filter(Attendance.emp_no == int(num_(request.args["emp_no"], "الموظف", 0, 10**9)))
    rows = q.order_by(Attendance.date.desc(), Attendance.in_time.desc()).limit(1000).all()
    names = names_map()
    return jsonify(rows=[att_out(a, names) for a in rows])


def apply_punch(emp, kind, date, tm, strict):
    st = get_settings()
    aid = f"{emp.emp_no}:{date}"
    row = db().get(Attendance, aid)
    if row is None:
        row = Attendance(id=aid, emp_no=emp.emp_no, date=date, in_time="", out_time="", status="حاضر")
        db().add(row)
    elif row.deleted:
        row.deleted, row.in_time, row.out_time = False, "", ""
    if kind == "in":
        if strict and row.in_time:
            raise ApiError("سجّلت حضورك اليوم مسبقاً")
        row.in_time = tm
        row.status = calc_status(tm, st)
    else:
        if strict and not row.in_time:
            raise ApiError("سجّل الحضور أولاً قبل الانصراف")
        if strict and row.out_time:
            raise ApiError("سجّلت انصرافك اليوم مسبقاً")
        row.out_time = tm
    stamp(row)
    return row


@app.post("/api/attendance/punch")
@require()
def punch():
    kind = body().get("kind")
    if kind not in ("in", "out"):
        raise ApiError("نوع الحركة غير صالح")
    u = g.user
    emp = db().get(Employee, u.emp_no) if u.emp_no is not None else None
    if not emp or emp.deleted:
        raise ApiError("حسابك غير مرتبط بموظف")
    if emp.status != "نشط":
        raise ApiError("حالتك الوظيفية موقوفة، لا يمكن تسجيل الحضور")
    n = now_local()
    row = apply_punch(emp, kind, n.strftime("%Y-%m-%d"), n.strftime("%H:%M"), strict=True)
    log(("تسجيل حضور: " if kind == "in" else "تسجيل انصراف: ") + emp.name)
    commit()
    return jsonify(row=att_out(row, {emp.emp_no: emp.name}))


@app.post("/api/attendance")
@require("admin")
def manual_attendance():
    d = body()
    kind = d.get("kind")
    if kind not in ("in", "out"):
        raise ApiError("نوع الحركة غير صالح")
    emp = db().get(Employee, int(num_(d.get("emp_no"), "الموظف", 0, 10**9)))
    if not emp or emp.deleted:
        raise ApiError("الموظف غير موجود", 404)
    row = apply_punch(emp, kind, date_(d.get("date"), "التاريخ"), time_(d.get("time"), "الوقت"), strict=False)
    log(("تسجيل يدوي للحضور: " if kind == "in" else "تسجيل يدوي للانصراف: ") + emp.name)
    commit()
    return jsonify(row=att_out(row, {emp.emp_no: emp.name}))


# ───────────────────────── الإجازات ─────────────────────────
@app.post("/api/leaves")
@require()
def add_leave():
    d = body()
    u = g.user
    if u.role == "admin":
        emp_no = int(num_(d.get("emp_no"), "الموظف", 0, 10**9))
    else:
        if u.emp_no is None:
            raise ApiError("حسابك غير مرتبط بموظف")
        emp_no = u.emp_no
    emp = db().get(Employee, emp_no)
    if not emp or emp.deleted:
        raise ApiError("الموظف غير موجود", 404)
    typ = s_(d.get("type"), "نوع الإجازة", 30)
    if typ not in LEAVE_TYPES:
        raise ApiError("نوع إجازة غير صالح")
    frm, to = date_(d.get("from"), "من تاريخ"), date_(d.get("to"), "إلى تاريخ")
    if to < frm:
        raise ApiError("تاريخ النهاية يجب أن يكون بعد البداية")
    l = Leave(emp_no=emp_no, type=typ, from_date=frm, to_date=to, reason=s_(d.get("reason"), "السبب", 300), status="معلّق")
    db().add(l)
    log("طلب إجازة جديد من " + emp.name)
    commit()
    return jsonify(ok=True), 201


@app.post("/api/leaves/<lid>/decision")
@require("admin")
def decide_leave(lid):
    status = body().get("status")
    if status not in ("مقبول", "مرفوض"):
        raise ApiError("قرار غير صالح")
    l = db().get(Leave, lid)
    if not l or l.deleted:
        raise ApiError("الطلب غير موجود", 404)
    if l.status != "معلّق":
        raise ApiError("تم البت في هذا الطلب مسبقاً")
    l.status, l.decided_by = status, g.user.username
    stamp(l)
    log(f"تم {status} طلب إجازة {names_map().get(l.emp_no, '')}")
    commit()
    return jsonify(ok=True)


@app.delete("/api/leaves/<lid>")
@require()
def cancel_leave(lid):
    l = db().get(Leave, lid)
    if not l or l.deleted:
        raise ApiError("الطلب غير موجود", 404)
    if g.user.role != "admin" and l.emp_no != g.user.emp_no:
        raise ApiError("ليست لديك صلاحية", 403)
    if l.status != "معلّق":
        raise ApiError("لا يمكن إلغاء طلب تم البت فيه")
    l.status = "ملغي"
    stamp(l)
    log("إلغاء طلب إجازة " + names_map().get(l.emp_no, ""))
    commit()
    return jsonify(ok=True)


# ───────────────────────── الرواتب ─────────────────────────
@app.get("/api/payroll")
@require()
def payroll():
    st = get_settings()
    q = db().query(Employee).filter_by(deleted=False)
    if g.user.role != "admin":
        if g.user.emp_no is None:
            return jsonify(rows=[])
        q = q.filter(Employee.emp_no == g.user.emp_no)
    return jsonify(rows=[payslip(e, st) for e in q.order_by(Employee.emp_no).all()])


# ───────────────────────── الإعدادات ─────────────────────────
@app.get("/api/settings")
@require("admin")
def get_settings_api():
    return jsonify(settings=get_settings())


@app.put("/api/settings")
@require("admin")
def put_settings():
    d = body()
    new = {
        "org": s_(d.get("org"), "اسم المؤسسة", 80),
        "currency": s_(d.get("currency"), "العملة", 10),
        "work_start": time_(d.get("work_start"), "بداية الدوام"),
        "grace_min": str(int(num_(d.get("grace_min"), "فترة السماح", 0, 240))),
        "allowance_pct": str(num_(d.get("allowance_pct"), "نسبة البدلات", 0, 100)),
        "deduction_pct": str(num_(d.get("deduction_pct"), "نسبة الاستقطاعات", 0, 100)),
    }
    for k, v in new.items():
        row = db().get(Setting, k)
        if row is None:
            db().add(Setting(key=k, value=v))
        else:
            row.value, row.deleted = v, False
            stamp(row)
    log("تم تحديث إعدادات النظام")
    commit()
    return jsonify(settings=get_settings())


# ───────────────────────── الحسابات ─────────────────────────
def active_admins():
    return db().query(User).filter_by(deleted=False, active=True, role="admin").count()


@app.get("/api/users")
@require("admin")
def list_users():
    names = names_map()
    us = db().query(User).filter_by(deleted=False).order_by(User.username).all()
    return jsonify(users=[{"id": u.id, "username": u.username, "role": u.role, "emp_no": u.emp_no,
                           "emp_name": names.get(u.emp_no, ""), "active": u.active} for u in us])


@app.post("/api/users")
@require("admin")
def add_user():
    d = body()
    role = d.get("role")
    if role not in ("admin", "employee"):
        raise ApiError("دور غير صالح")
    emp_no = None
    if d.get("emp_no") not in (None, ""):
        emp_no = int(num_(d.get("emp_no"), "الموظف", 0, 10**9))
        e = db().get(Employee, emp_no)
        if not e or e.deleted:
            raise ApiError("الموظف غير موجود", 404)
    if role == "employee" and emp_no is None:
        raise ApiError("حساب الموظف يجب ربطه بموظف")
    u = create_user(d.get("username"), d.get("password"), role, emp_no)
    log(f"تم إنشاء حساب {u.username} ({'مدير' if role == 'admin' else 'موظف'})")
    commit()
    return jsonify(ok=True), 201


@app.put("/api/users/<uid>")
@require("admin")
def edit_user(uid):
    d = body()
    u = db().get(User, uid)
    if not u or u.deleted:
        raise ApiError("الحساب غير موجود", 404)
    me_ = g.user
    if "role" in d and d["role"] != u.role:
        if d["role"] not in ("admin", "employee"):
            raise ApiError("دور غير صالح")
        if u.id == me_.id:
            raise ApiError("لا يمكنك تغيير صلاحية حسابك")
        if d["role"] == "employee" and u.emp_no is None:
            raise ApiError("اربط الحساب بموظف أولاً")
        u.role = d["role"]
    if "active" in d and bool(d["active"]) != u.active:
        if u.id == me_.id:
            raise ApiError("لا يمكنك تعطيل حسابك")
        u.active = bool(d["active"])
    if d.get("password"):
        u.password_hash = hash_pw(check_password(d["password"]))
        u.must_change = True
    if active_admins() < 1 and (u.role != "admin" or not u.active):
        db().rollback()
        raise ApiError("يجب أن يبقى مدير فعّال واحد على الأقل")
    stamp(u)
    log("تعديل الحساب " + u.username)
    commit()
    return jsonify(ok=True)


@app.delete("/api/users/<uid>")
@require("admin")
def del_user(uid):
    u = db().get(User, uid)
    if not u or u.deleted:
        raise ApiError("الحساب غير موجود", 404)
    if u.id == g.user.id:
        raise ApiError("لا يمكنك حذف حسابك")
    if u.role == "admin" and u.active and active_admins() <= 1:
        raise ApiError("يجب أن يبقى مدير فعّال واحد على الأقل")
    u.deleted, u.active = True, False
    stamp(u)
    log("حذف الحساب " + u.username)
    commit()
    return jsonify(ok=True)


# ───────────────────────── المزامنة والصحة ─────────────────────────
@app.get("/api/sync/status")
@require("admin")
def sync_status():
    return jsonify(sync.status())


@app.post("/api/sync/run")
@require("admin")
def sync_run():
    sync.run_sync()
    return jsonify(sync.status())


@app.get("/api/health")
def health():
    try:
        db().query(Setting).first()
        return jsonify(ok=True)
    except Exception:
        return jsonify(ok=False), 503


# ───────────────────────── الواجهة ─────────────────────────
@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "same-origin"
    r.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                            "script-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                            "connect-src 'self'; manifest-src 'self'; worker-src 'self'")
    if request.path.startswith("/api/") or request.path in ("/", "/sw.js", "/index.html"):
        r.headers["Cache-Control"] = "no-store" if request.path.startswith("/api/") else "no-cache"
    return r


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ───────────────────────── التهيئة ─────────────────────────
def seed():
    s = D.PrimarySession()
    try:
        if not s.query(Department).filter_by(deleted=False).count():
            s.add(Department(name="الإدارة", manager="غير محدد"))
        if not s.query(User).filter_by(deleted=False, role="admin").count():
            pw = config.ADMIN_PASSWORD
            generated = not pw
            if generated:
                pw = secrets.token_urlsafe(9)
            s.add(User(username=config.ADMIN_USERNAME, password_hash=hash_pw(pw), role="admin",
                       emp_no=None, active=True, must_change=generated))
            bar = "═" * 52
            print(f"\n{bar}\n  تم إنشاء حساب المدير الأول\n  اسم المستخدم : {config.ADMIN_USERNAME}\n"
                  f"  كلمة المرور  : {pw}\n  {'(سيُطلب منك تغييرها عند أول دخول)' if generated else ''}\n{bar}\n", flush=True)
        if config.SEED_DEMO and not s.query(Employee).count():
            demo = [(1001, "محمد خالد", "تقنية المعلومات", "مطور برمجيات", "2024-02-12", 1800000),
                    (1002, "سارة أحمد", "المحاسبة", "محاسبة", "2023-08-20", 1450000),
                    (1003, "علي حسن", "المبيعات", "مندوب مبيعات", "2024-05-03", 1300000)]
            for dep in {x[2] for x in demo}:
                s.add(Department(name=dep, manager="غير محدد"))
            for n, name, dep, job, hire, sal in demo:
                s.add(Employee(emp_no=n, name=name, department=dep, job=job, hire=hire, salary=sal, status="نشط"))
        s.commit()
    finally:
        s.close()
    sync.request_sync()


def init():
    D.ensure_schema(D.primary_engine)
    if D.secondary_engine is not None:
        sync.run_sync()  # سحب أي بيانات موجودة على الإنترنت قبل إنشاء بيانات أولية
    seed()
    sync.start_background()


init()

if __name__ == "__main__":
    from waitress import serve
    print(f"▶ http://localhost:{config.PORT}  |  القاعدة الأساسية: {D.kind_of(D.primary_engine)}"
          + (f"  |  مزامنة مع: {D.kind_of(D.secondary_engine)}" if D.secondary_engine is not None else ""))
    serve(app, host=config.HOST, port=config.PORT, threads=8)
