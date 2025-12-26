import os
import sys
import traceback

import psycopg2


def masked(value: str | None) -> str | None:
    if value is None:
        return None
    if len(value) <= 2:
        return "***"
    return value[0] + "***" + value[-1]


def main() -> int:
    params = {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": int(os.getenv("DB_PORT", "5432")),
        "dbname": os.getenv("DB_NAME", "securesys_db"),
        "user": os.getenv("DB_USER", "securesys_user"),
        "password": os.getenv("DB_PASSWORD", ""),
    }

    printable = dict(params)
    printable["password"] = masked(printable.get("password"))
    print("DB params:", printable)

    try:
        conn = psycopg2.connect(**params)
        cur = conn.cursor()
        cur.execute("select version()")
        print("Connected OK:", cur.fetchone()[0])
        cur.close()
        conn.close()
        return 0
    except Exception as e:
        print("Connect failed")
        print("type:", type(e))
        print("str:", str(e))
        print("repr:", repr(e))
        print("pgerror:", getattr(e, "pgerror", None))
        diag = getattr(e, "diag", None)
        if diag is not None:
            for attr in [
                "severity",
                "sqlstate",
                "message_primary",
                "message_detail",
                "message_hint",
            ]:
                print(f"diag.{attr}:", getattr(diag, attr, None))
        traceback.print_exc()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
