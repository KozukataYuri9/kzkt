import hmac
import http.client
import ipaddress
import json
import os
import platform
import re
import secrets
import socket
import ssl
import sqlite3
import subprocess
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from decimal import Decimal, InvalidOperation

from flask import Flask, abort, render_template, request, redirect, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config.update(
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "users.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
PAGES_DIR = os.path.join(BASE_DIR, "pages")
MAX_RECHARGE_AMOUNT = Decimal("1000000.00")
MONEY_QUANTUM = Decimal("0.01")
ALLOWED_FETCH_SCHEMES = {"http": 80, "https": 443}
FETCH_TIMEOUT_SECONDS = 10
MAX_FETCH_BYTES = 20000
MAX_FETCH_CHARACTERS = 5000
MAX_XML_IMPORT_CHARACTERS = 100000

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


def generate_csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def rotate_csrf_token():
    session["_csrf_token"] = secrets.token_urlsafe(32)
    return session["_csrf_token"]


app.jinja_env.globals["csrf_token"] = generate_csrf_token


@app.before_request
def validate_csrf_token():
    if request.method != "POST":
        return None

    if request.endpoint == "fetch_url" and not session.get("username"):
        return None

    session_token = session.get("_csrf_token", "")
    request_token = request.form.get("csrf_token", "") or request.headers.get(
        "X-CSRF-Token", ""
    )
    if not session_token or not request_token:
        abort(400, description="CSRF token 缺失或无效")

    if not hmac.compare_digest(session_token, request_token):
        abort(400, description="CSRF token 缺失或无效")

    return None


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


def get_auth_user_by_username(username):
    if not username:
        return None

    conn = get_db_connection()
    user = conn.execute(
        "SELECT username, password FROM users WHERE username = ?",
        (username,),
    ).fetchone()
    conn.close()
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
        user = get_auth_user_by_username(username)

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["username"] = username
            rotate_csrf_token()
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


class UnsafeFetchTarget(ValueError):
    pass


def read_response_preview(response):
    raw_content = response.read(MAX_FETCH_BYTES)
    charset = response.headers.get_content_charset() or "utf-8"
    try:
        return raw_content.decode(charset, errors="replace")[:MAX_FETCH_CHARACTERS]
    except LookupError:
        return raw_content.decode("utf-8", errors="replace")[:MAX_FETCH_CHARACTERS]


def resolve_public_addresses(hostname, port):
    try:
        address_info = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as error:
        raise UnsafeFetchTarget("目标域名无法解析") from error

    addresses = []
    for entry in address_info:
        address = entry[4][0]
        try:
            parsed_address = ipaddress.ip_address(address)
        except ValueError as error:
            raise UnsafeFetchTarget("目标地址无效") from error

        if not parsed_address.is_global:
            raise UnsafeFetchTarget("禁止访问内网、回环或其他非公网地址")
        if address not in addresses:
            addresses.append(address)

    if not addresses:
        raise UnsafeFetchTarget("目标域名没有可用的公网地址")
    return addresses


def validate_fetch_target(target_url):
    try:
        parsed = urllib.parse.urlsplit(target_url)
    except ValueError as error:
        raise UnsafeFetchTarget("URL 格式无效") from error

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_FETCH_SCHEMES:
        raise UnsafeFetchTarget("只允许使用 http:// 或 https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeFetchTarget("URL 中不能包含用户名或密码")
    if not parsed.hostname:
        raise UnsafeFetchTarget("URL 缺少有效主机名")

    try:
        hostname = parsed.hostname.encode("idna").decode("ascii")
        port = parsed.port or ALLOWED_FETCH_SCHEMES[scheme]
    except (UnicodeError, ValueError) as error:
        raise UnsafeFetchTarget("URL 主机名或端口无效") from error

    lowered_hostname = hostname.rstrip(".").lower()
    if (
        lowered_hostname == "localhost"
        or lowered_hostname.endswith(".localhost")
        or lowered_hostname.endswith(".local")
    ):
        raise UnsafeFetchTarget("禁止访问本地主机名")

    if port != ALLOWED_FETCH_SCHEMES[scheme]:
        raise UnsafeFetchTarget("只允许访问 HTTP/HTTPS 默认端口")

    addresses = resolve_public_addresses(hostname, port)
    request_target = parsed.path or "/"
    if parsed.query:
        request_target = f"{request_target}?{parsed.query}"
    return scheme, hostname, port, request_target, addresses


def create_pinned_connection(scheme, hostname, port, address):
    if scheme == "https":
        connection = http.client.HTTPSConnection(
            hostname,
            port,
            timeout=FETCH_TIMEOUT_SECONDS,
            context=ssl.create_default_context(),
        )
    else:
        connection = http.client.HTTPConnection(
            hostname,
            port,
            timeout=FETCH_TIMEOUT_SECONDS,
        )

    def pinned_create_connection(
        _destination,
        timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
        source_address=None,
        *args,
        **kwargs,
    ):
        return socket.create_connection((address, port), timeout, source_address)

    connection._create_connection = pinned_create_connection
    return connection


def secure_fetch(target_url):
    scheme, hostname, port, request_target, addresses = validate_fetch_target(
        target_url
    )
    connection = create_pinned_connection(
        scheme,
        hostname,
        port,
        addresses[0],
    )
    try:
        connection.request(
            "GET",
            request_target,
            headers={
                "User-Agent": "SecureURLFetcher/1.0",
                "Accept": "text/plain,text/html,application/json;q=0.9,*/*;q=0.1",
            },
        )
        response = connection.getresponse()
        return response.status, read_response_preview(response)
    finally:
        connection.close()


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    username = session.get("username")
    user = public_user_info(username)
    if not user:
        return redirect("/login")

    target_url = request.form.get("url", "")
    try:
        status_code, content = secure_fetch(target_url)
        return render_template(
            "index.html",
            user=user,
            fetch_url=target_url,
            fetch_status=status_code,
            fetch_content=content,
        )
    except UnsafeFetchTarget as error:
        return render_template(
            "index.html",
            user=user,
            fetch_url=target_url,
            fetch_error=f"抓取失败：{error}",
        ), 400
    except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as error:
        app.logger.warning("URL fetch failed for %r: %s", target_url, error)
        return render_template(
            "index.html",
            user=user,
            fetch_url=target_url,
            fetch_error="抓取失败：目标不可访问或响应异常",
        ), 502


@app.route("/ping", methods=["GET", "POST"])
def ping():
    if not session.get("username"):
        return redirect("/login")

    if request.method == "GET":
        return render_template("ping.html")

    ip_value = request.form.get("ip", "").strip()
    try:
        target_ip = str(ipaddress.ip_address(ip_value))
    except ValueError:
        return render_template(
            "ping.html",
            ip=ip_value,
            error="请输入有效的 IPv4 或 IPv6 地址",
        ), 400

    count_option = "-n" if platform.system() == "Windows" else "-c"
    command = ["ping", count_option, "3", target_ip]
    try:
        output = subprocess.check_output(
            command,
            stderr=subprocess.STDOUT,
            shell=False,
            timeout=30,
            text=True,
            errors="replace",
        )
        return render_template("ping.html", ip=target_ip, output=output)
    except subprocess.CalledProcessError as error:
        return render_template(
            "ping.html",
            ip=target_ip,
            output=error.output or "Ping 执行失败",
            error="目标不可达或 Ping 命令执行失败",
        )
    except subprocess.TimeoutExpired as error:
        timeout_output = error.output or ""
        if isinstance(timeout_output, bytes):
            timeout_output = timeout_output.decode(errors="replace")
        return render_template(
            "ping.html",
            ip=target_ip,
            output=timeout_output,
            error="Ping 执行超时",
        ), 504
    except OSError:
        app.logger.exception("Unable to start the ping command")
        return render_template(
            "ping.html",
            ip=target_ip,
            error="服务器无法启动 Ping 命令",
        ), 500


def local_xml_name(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def xml_child_text(node, child_name):
    for child in node:
        if local_xml_name(child.tag) == child_name:
            return (child.text or "").strip()
    return ""


@app.route("/xml-import", methods=["GET", "POST"])
def xml_import():
    if not session.get("username"):
        return redirect("/login")

    if request.method == "GET":
        return render_template("xml_import.html")

    xml_data = request.form.get("xml_data", "")
    if not xml_data.strip():
        return render_template(
            "xml_import.html",
            xml_data=xml_data,
            error="请输入 XML 数据",
        ), 400
    if len(xml_data) > MAX_XML_IMPORT_CHARACTERS:
        return render_template(
            "xml_import.html",
            error="XML 数据过大",
        ), 413

    dangerous_declaration = re.search(
        r"<!\s*(?:DOCTYPE|ENTITY)\b|\b(?:SYSTEM|PUBLIC)\b",
        xml_data,
        re.IGNORECASE,
    )
    if dangerous_declaration:
        return render_template(
            "xml_import.html",
            xml_data=xml_data,
            error="禁止使用 DTD、实体或外部资源声明",
        ), 400

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as error:
        return render_template(
            "xml_import.html",
            xml_data=xml_data,
            error=f"XML 解析失败：{error}",
        ), 400

    users = []
    for node in root.iter():
        if local_xml_name(node.tag) != "user":
            continue
        users.append(
            {
                "name": (node.get("name") or xml_child_text(node, "name")).strip(),
                "email": (
                    node.get("email") or xml_child_text(node, "email")
                ).strip(),
            }
        )

    result = json.dumps(
        {"count": len(users), "users": users},
        ensure_ascii=False,
        indent=2,
    )
    return render_template(
        "xml_import.html",
        xml_data=xml_data,
        result=result,
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


@app.route("/change-password", methods=["POST"])
def change_password():
    username = session.get("username")
    if not username:
        return redirect("/login")

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    profile_user = get_user_by_username(username)
    auth_user = get_auth_user_by_username(username)

    if not profile_user or not auth_user:
        session.clear()
        return redirect("/login")

    if not check_password_hash(auth_user["password"], current_password):
        return (
            render_template(
                "profile.html",
                profile_user=profile_user,
                error="原密码不正确",
            ),
            400,
        )

    if len(new_password) < 8:
        return (
            render_template(
                "profile.html",
                profile_user=profile_user,
                error="新密码长度至少为 8 位",
            ),
            400,
        )

    if new_password != confirm_password:
        return (
            render_template(
                "profile.html",
                profile_user=profile_user,
                error="两次输入的新密码不一致",
            ),
            400,
        )

    conn = get_db_connection()
    conn.execute(
        "UPDATE users SET password = ? WHERE username = ?",
        (generate_password_hash(new_password), username),
    )
    conn.commit()
    conn.close()
    rotate_csrf_token()

    return redirect("/profile")


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


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5001, debug=True)
