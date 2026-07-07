from flask import Flask, render_template, request, redirect, session
from werkzeug.security import check_password_hash


app = Flask(__name__)
app.secret_key = "dev-key-2025"

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

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
