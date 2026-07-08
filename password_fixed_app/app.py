import sqlite3, os

from flask import Flask, render_template, request, redirect, session
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.secret_key = "dev-key-2025"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "users.db")

USERS = {
    "admin": {
        "password_hash": "scrypt:32768:8:1$iRhmEu26Hv0IgndS$fe0c49ed06465d3dc5887aaadcaff950515cd6b7b444c871a19da57d48a599d90ecd6b2407a58358fdfc0bd234780b696e05852feaf8a046564123befc779d2b",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "password_hash": "scrypt:32768:8:1$cAUMnqnuBJNTq81G$93ae45943702db7bf072296d2021b18348f572f24616c97e591033f68a0a823e4bea0af65c01d925a9d0169b242b261c492fc29d1f0ae08ce64b4a233e502a9f",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            phone TEXT
        )
        """
    )
    cursor.execute(
        """
        INSERT OR IGNORE INTO users (username, password, email, phone)
        VALUES (?, ?, ?, ?)
        """,
        (
            "admin",
            USERS["admin"]["password_hash"],
            "admin@example.com",
            "13800138000",
        ),
    )
    cursor.execute(
        """
        INSERT OR IGNORE INTO users (username, password, email, phone)
        VALUES (?, ?, ?, ?)
        """,
        (
            "alice",
            USERS["alice"]["password_hash"],
            "alice@example.com",
            "13900139001",
        ),
    )

    users = cursor.execute("SELECT id, password FROM users").fetchall()
    for user_id, stored_password in users:
        if not stored_password.startswith(("scrypt:", "pbkdf2:")):
            cursor.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (generate_password_hash(stored_password), user_id),
            )
    connection.commit()
    connection.close()


def public_user_info(username):
    user = USERS.get(username)
    if not user:
        return None
    return {
        "username": username,
        "role": user["role"],
        "email": user["email"],
        "phone": user["phone"],
        "balance": user["balance"],
    }


@app.route("/")
def index():
    username = session.get("username")
    return render_template("index.html", user=public_user_info(username))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = USERS.get(username)

        if user and check_password_hash(user["password_hash"], password):
            session["username"] = username
            return render_template("index.html", user=public_user_info(username))

        return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html", message=request.args.get("message"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        sql = """
            INSERT INTO users (username, password, email, phone)
            VALUES (?, ?, ?, ?)
        """
        password_hash = generate_password_hash(password)
        connection = sqlite3.connect(DB_PATH)
        try:
            connection.execute(sql, (username, password_hash, email, phone))
            connection.commit()
        except sqlite3.IntegrityError:
            connection.close()
            return render_template("register.html", error="用户名已存在")
        except sqlite3.Error:
            connection.close()
            return render_template("register.html", error="注册失败，请稍后重试")
        connection.close()
        return redirect("/login?message=注册成功，请登录")

    return render_template("register.html")


@app.route("/search")
def search():
    username = session.get("username")
    user = public_user_info(username)
    if not user:
        return redirect("/login")

    keyword = request.args.get("keyword", "")
    sql = """
        SELECT id, username, email, phone
        FROM users
        WHERE username LIKE ? OR email LIKE ?
    """
    search_pattern = f"%{keyword}%"

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    results = connection.execute(
        sql,
        (search_pattern, search_pattern),
    ).fetchall()
    connection.close()

    return render_template(
        "index.html",
        user=user,
        keyword=keyword,
        results=results,
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5001, debug=True)
