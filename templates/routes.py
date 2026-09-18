import json
import os
import secrets
import sqlite3

from cryptography.fernet import InvalidToken
from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from encryption import decrypt_entry, derive_key, encrypt_entry
from extensions import ACTIVE_KEYS, get_user_key, login_required
from forms import credential_form_data, valid_csrf_token
from models import create_database, get_db_connection


routes = Blueprint("routes", __name__)


@routes.before_app_request
def prepare_database():
    create_database()


@routes.route("/")
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
            data = decrypt_entry(row["encrypted_data"], get_user_key())
            data["id"] = row["id"]
            entries.append(data)
        except (InvalidToken, json.JSONDecodeError):
            flash("One vault entry could not be decrypted.", "danger")
    return render_template("index_page.html", entries=entries)


@routes.route("/register", methods=["GET", "POST"])
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
        connection = get_db_connection()
        try:
            connection.execute(
                "INSERT INTO users (username, password_hash, encryption_salt) VALUES (?, ?, ?)",
                (username, generate_password_hash(master_password), os.urandom(16)),
            )
            connection.commit()
        except sqlite3.IntegrityError:
            flash("That username is already registered.", "danger")
            return render_template("register.html")
        finally:
            connection.close()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("routes.login"))
    return render_template("register.html")


@routes.route("/login", methods=["GET", "POST"])
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
            return redirect(url_for("routes.index"))
        flash("Invalid username or master password.", "danger")
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return render_template("login.html")


@routes.post("/logout")
def logout():
    if not valid_csrf_token():
        return redirect(url_for("routes.index"))
    ACTIVE_KEYS.pop(session.get("session_id"), None)
    session.clear()
    return redirect(url_for("routes.login"))


def find_entry(entry_id):
    connection = get_db_connection()
    row = connection.execute(
        "SELECT id, encrypted_data FROM vault_entries WHERE id = ? AND user_id = ?",
        (entry_id, session["user_id"]),
    ).fetchone()
    connection.close()
    if row is None:
        return None
    data = decrypt_entry(row["encrypted_data"], get_user_key())
    data["id"] = row["id"]
    return data


def save_entry(entry_id=None):
    data = credential_form_data()
    if not all(data.values()):
        flash("All fields are required.", "danger")
        return False
    connection = get_db_connection()
    encrypted_data = encrypt_entry(data, get_user_key())
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


@routes.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        if not valid_csrf_token():
            flash("Invalid form token. Please try again.", "danger")
        elif save_entry():
            return redirect(url_for("routes.index"))
    return render_template("entry_form.html", title="Add credential", entry=None)


@routes.route("/update/<int:entry_id>", methods=["GET", "POST"])
@login_required
def update(entry_id):
    entry = find_entry(entry_id)
    if entry is None:
        return "Entry not found", 404
    if request.method == "POST":
        if not valid_csrf_token():
            flash("Invalid form token. Please try again.", "danger")
        elif save_entry(entry_id):
            return redirect(url_for("routes.index"))
    return render_template("entry_form.html", title="Edit credential", entry=entry)


@routes.post("/delete/<int:entry_id>")
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
    return redirect(url_for("routes.index"))