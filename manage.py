"""أدوات إدارة من سطر الأوامر

  python manage.py create-admin <username> <password>   إنشاء حساب مدير جديد
  python manage.py reset-password <username> <password> تعيين كلمة مرور (مفيد إن نسيت كلمة مرور المدير)
  python manage.py sync                                  مزامنة فورية بين القاعدتين
"""
import sys

import app as A
import database as D
import sync
from database import User, stamp


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    cmd = argv[1]
    if cmd == "sync":
        st = sync.run_sync()
        print("خطأ:" if st["last_error"] else "تمت المزامنة.", st["last_error"] or f"أُرسل {st['pushed']} / استُلم {st['pulled']}")
        return 0
    if cmd in ("create-admin", "reset-password") and len(argv) == 4:
        username, pw = argv[2].lower(), argv[3]
        try:
            A.check_password(pw)
        except A.ApiError as e:
            print(e.msg)
            return 1
        with D.PrimarySession() as s:
            u = s.query(User).filter_by(username=username, deleted=False).first()
            if cmd == "create-admin":
                if u:
                    print("اسم المستخدم موجود مسبقاً")
                    return 1
                if not A.USER_RE.match(username):
                    print("اسم المستخدم غير صالح")
                    return 1
                s.add(User(username=username, password_hash=A.hash_pw(pw), role="admin", active=True, must_change=False))
            else:
                if not u:
                    print("المستخدم غير موجود")
                    return 1
                u.password_hash, u.active, u.must_change = A.hash_pw(pw), True, True
                stamp(u)
            s.commit()
        sync.request_sync()
        sync.run_sync()
        print("تم.")
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
