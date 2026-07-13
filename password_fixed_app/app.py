import os
import sqlite3
import uuid
from decimal import Decimal, InvalidOperation

from flask import Flask, abort, render_template, request, redirect, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.secret_key = "dev-key-2025"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "users.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
PAGES_DIR = os.path.join(BASE_DIR, "pages")
MAX_RECHARGE_AMOUNT = Decimal("1000000.00")
MONEY_QUANTUM = Decimal("0.01")

ALLOWED_PAGES = {
    "help": "help.html",
    "help.html": "help.html",
}

ALLOWED_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}
ALLOWED_IMAGE_MIME_TYPES = {
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/webp",
}

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


def get_db_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    connection = get_db_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            phone TEXT,
            balance REAL DEFAULT 0
        )
        """
    )

    columns = [row["name"] for row in cursor.execute("PRAGMA table_info(users)").fetchall()]
    if "balance" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0")
        cursor.execute(
            "UPDATE users SET balance = ? WHERE username = ?",
            (USERS["admin"]["balance"], "admin"),
        )
        cursor.execute(
            "UPDATE users SET balance = ? WHERE username = ?",
            (USERS["alice"]["balance"], "alice"),
        )

    cursor.execute(
        """
        INSERT OR IGNORE INTO users (username, password, email, phone, balance)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "admin",
            USERS["admin"]["password_hash"],
            USERS["admin"]["email"],
            USERS["admin"]["phone"],
            USERS["admin"]["balance"],
        ),
    )
    cursor.execute(
        """
        INSERT OR IGNORE INTO users (username, password, email, phone, balance)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "alice",
            USERS["alice"]["password_hash"],
            USERS["alice"]["email"],
            USERS["alice"]["phone"],
            USERS["alice"]["balance"],
        ),
    )

    users = cursor.execute("SELECT id, password FROM users").fetchall()
    for user in users:
        stored_password = user["password"]
        if stored_password and not stored_password.startswith(("scrypt:", "pbkdf2:")):
            cursor.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (generate_password_hash(stored_password), user["id"]),
            )

    connection.commit()
    connection.close()


def get_user_by_username(username):
    if not username:
        return None
    connection = get_db_connection()
    user = connection.execute(
        "SELECT id, username, email, phone, balance FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    connection.close()
    return user


def public_user_info(username):
    user = USERS.get(username)
    db_user = get_user_by_username(username)
    if not user or not db_user:
        return None
    return {
        "id": db_user["id"],
        "username": username,
        "role": user["role"],
        "email": db_user["email"],
        "phone": db_user["phone"],
        "balance": db_user["balance"],
    }


def detect_image_type(header):
    if header.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if header.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if header.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "webp"
    return None


def validate_avatar_file(file):
    original_filename = file.filename or ""
    safe_original_name = secure_filename(original_filename)
    if not safe_original_name or "." not in safe_original_name:
        return None, "文件名无效，请上传 jpg、jpeg、png、gif 或 webp 图片"

    extension = safe_original_name.rsplit(".", 1)[1].lower()
    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        return None, "只允许上传 jpg、jpeg、png、gif 或 webp 图片"

    if file.mimetype not in ALLOWED_IMAGE_MIME_TYPES:
        return None, "文件类型不是允许的图片类型"

    header = file.stream.read(16)
    file.stream.seek(0)
    detected_type = detect_image_type(header)
    normalized_extension = "jpeg" if extension in {"jpg", "jpeg"} else extension
    if detected_type != normalized_extension:
        return None, "文件内容不是有效的图片"

    saved_filename = f"{uuid.uuid4().hex}.{extension}"
    return saved_filename, None


@app.route("/")
def index():
    username = session.get("username")
    return render_template("index.html", user=public_user_info(username))


@app.route("/page")
def page():
    name = request.args.get("name", "")
    page_filename = ALLOWED_PAGES.get(name)

    if page_filename:
        file_path = os.path.join(PAGES_DIR, page_filename)
        if os.path.isfile(file_path):
            with open(file_path, "r", encoding="utf-8") as page_file:
                page_content = page_file.read()
        else:
            page_content = "页面不存在"
    else:
        page_content = "页面不存在"

    username = session.get("username")
    return render_template(
        "index.html",
        user=public_user_info(username),
        page_content=page_content,
    )


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

        password_hash = generate_password_hash(password)
        connection = get_db_connection()
        try:
            connection.execute(
                """
                INSERT INTO users (username, password, email, phone, balance)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, password_hash, email, phone, 0),
            )
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

    connection = get_db_connection()
    results = connection.execute(sql, (search_pattern, search_pattern)).fetchall()
    connection.close()

    return render_template(
        "index.html",
        user=user,
        keyword=keyword,
        results=results,
    )


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if not session.get("username"):
        return redirect("/login")

    if request.method == "POST":
        file = request.files.get("avatar")
        if not file or file.filename == "":
            return render_template("upload.html", error="请选择要上传的文件")

        filename, error = validate_avatar_file(file)
        if error:
            return render_template("upload.html", error=error)

        os.makedirs(UPLOAD_DIR, exist_ok=True)
        save_path = os.path.join(UPLOAD_DIR, filename)
        file.save(save_path)
        file_url = url_for("static", filename=f"uploads/{filename}")
        return render_template(
            "upload.html",
            filename=filename,
            original_filename=secure_filename(file.filename),
            file_url=file_url,
        )

    return render_template("upload.html")


@app.route("/profile")
def profile():
    username = session.get("username")
    if not username:
        return redirect("/login")

    profile_user = get_user_by_username(username)
    if not profile_user:
        session.clear()
        return redirect("/login")

    requested_user_id = request.args.get("user_id")
    if requested_user_id is not None:
        try:
            if int(requested_user_id) != profile_user["id"]:
                abort(403)
        except (TypeError, ValueError):
            abort(403)

    return render_template("profile.html", profile_user=profile_user)


@app.route("/recharge", methods=["POST"])
def recharge():
    username = session.get("username")
    if not username:
        return redirect("/login")

    current_user = get_user_by_username(username)
    if not current_user:
        session.clear()
        return redirect("/login")

    amount_text = request.form.get("amount", "").strip()
    try:
        amount = Decimal(amount_text)
    except (InvalidOperation, ValueError):
        amount = Decimal("NaN")

    try:
        has_valid_precision = amount.quantize(MONEY_QUANTUM) == amount
    except InvalidOperation:
        has_valid_precision = False

    is_valid_amount = (
        amount.is_finite()
        and amount > 0
        and amount <= MAX_RECHARGE_AMOUNT
        and has_valid_precision
    )
    if not is_valid_amount:
        return (
            render_template(
                "profile.html",
                profile_user=current_user,
                error="充值金额必须大于 0、最多保留两位小数，且不能超过 1000000 元",
            ),
            400,
        )

    connection = get_db_connection()
    connection.execute(
        "UPDATE users SET balance = ROUND(balance + ?, 2) WHERE id = ?",
        (float(amount), current_user["id"]),
    )
    connection.commit()
    connection.close()

    return redirect("/profile")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5001, debug=True)
