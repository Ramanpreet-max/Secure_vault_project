import base64
import json
import os
import secrets
import sqlite3
from functools import wraps
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__, template_folder="../templates")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "development-key-change-me")
DATABASE = Path(__file__).resolve().parent.parent / "passwords.db"
ACTIVE_KEYS = {}


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def create_database():
    connection = get_db_connection()
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            encryption_salt BLOB NOT NULL
        );
        CREATE TABLE IF NOT EXISTS vault_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            encrypted_data TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
        """
    )
    connection.commit()
    connection.close()


def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def get_user_key():
    session_id = session.get("session_id")
    return ACTIVE_KEYS.get(session_id)


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not get_user_key():
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def valid_csrf_token():
    return secrets.compare_digest(
        request.form.get("csrf_token", ""), session.get("csrf_token", "")
    )


@app.context_processor
def template_helpers():
    return {"csrf_token": session.get("csrf_token", "")}


create_database()


@app.route("/")
@login_required
def index():
    connection = get_db_connection()
    rows = connection.execute(
        "SELECT id, encrypted_data FROM vault_entries WHERE user_id = ? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    connection.close()

    entries = []
    for row in rows:
        try:
            data = json.loads(Fernet(get_user_key()).decrypt(row["encrypted_data"]).decode())
            data["id"] = row["id"]
            entries.append(data)
        except (InvalidToken, json.JSONDecodeError):
            flash("One vault entry could not be decrypted.", "danger")

    return render_template("index_page.html", entries=entries)


@app.route("/register", methods=["GET", "POST"])
def register():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    if request.method == "POST":
        if not valid_csrf_token():
            flash("Invalid form token. Please try again.", "danger")
            return render_template("register.html")
        username = request.form.get("username", "").strip()
        master_password = request.form.get("master_password", "")
        if len(username) < 3 or len(master_password) < 8:
            flash("Username needs 3 characters and master password needs 8.", "danger")
            return render_template("register.html")

        salt = os.urandom(16)
        connection = get_db_connection()
        try:
            connection.execute(
                "INSERT INTO users (username, password_hash, encryption_salt) VALUES (?, ?, ?)",
                (username, generate_password_hash(master_password), salt),
            )
            connection.commit()
        except sqlite3.IntegrityError:
            flash("That username is already registered.", "danger")
            return render_template("register.html")
        finally:
            connection.close()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not valid_csrf_token():
            flash("Invalid form token. Please try again.", "danger")
            return render_template("login.html")
        username = request.form.get("username", "").strip()
        master_password = request.form.get("master_password", "")
        connection = get_db_connection()
        user = connection.execute(
            "SELECT id, username, password_hash, encryption_salt FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        connection.close()

        if user and check_password_hash(user["password_hash"], master_password):
            session.clear()
            session["session_id"] = secrets.token_urlsafe(32)
            session["csrf_token"] = secrets.token_urlsafe(32)
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            ACTIVE_KEYS[session["session_id"]] = derive_key(
                master_password, user["encryption_salt"]
            )
            return redirect(url_for("index"))
        flash("Invalid username or master password.", "danger")

    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return render_template("login.html")


@app.post("/logout")
def logout():
    if not valid_csrf_token():
        return redirect(url_for("index"))
    ACTIVE_KEYS.pop(session.get("session_id"), None)
    session.clear()
    return redirect(url_for("login"))


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        if not valid_csrf_token():
            flash("Invalid form token. Please try again.", "danger")
        elif save_entry():
            return redirect(url_for("index"))
    return render_template("entry_form.html", title="Add credential", entry=None)


@app.route("/update/<int:entry_id>", methods=["GET", "POST"])
@login_required
def update(entry_id):
    entry = find_entry(entry_id)
    if entry is None:
        return "Entry not found", 404
    if request.method == "POST":
        if not valid_csrf_token():
            flash("Invalid form token. Please try again.", "danger")
        elif save_entry(entry_id):
            return redirect(url_for("index"))
    return render_template("entry_form.html", title="Edit credential", entry=entry)


def find_entry(entry_id):
    connection = get_db_connection()
    row = connection.execute(
        "SELECT id, encrypted_data FROM vault_entries WHERE id = ? AND user_id = ?",
        (entry_id, session["user_id"]),
    ).fetchone()
    connection.close()
    if row is None:
        return None
    data = json.loads(Fernet(get_user_key()).decrypt(row["encrypted_data"]).decode())
    data["id"] = row["id"]
    return data


def save_entry(entry_id=None):
    data = {
        "site": request.form.get("site", "").strip(),
        "username": request.form.get("username", "").strip(),
        "password": request.form.get("password", ""),
    }
    if not all(data.values()):
        flash("All fields are required.", "danger")
        return False
    encrypted_data = Fernet(get_user_key()).encrypt(json.dumps(data).encode()).decode()
    connection = get_db_connection()
    if entry_id is None:
        connection.execute(
            "INSERT INTO vault_entries (user_id, encrypted_data) VALUES (?, ?)",
            (session["user_id"], encrypted_data),
        )
    else:
        connection.execute(
            "UPDATE vault_entries SET encrypted_data = ? WHERE id = ? AND user_id = ?",
            (encrypted_data, entry_id, session["user_id"]),
        )
    connection.commit()
    connection.close()
    return True


@app.post("/delete/<int:entry_id>")
@login_required
def delete(entry_id):
    if valid_csrf_token():
        connection = get_db_connection()
        connection.execute(
            "DELETE FROM vault_entries WHERE id = ? AND user_id = ?",
            (entry_id, session["user_id"]),
        )
        connection.commit()
        connection.close()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)

