import secrets

from flask import request, session


def valid_csrf_token():
    return secrets.compare_digest(
        request.form.get("csrf_token", ""), session.get("csrf_token", "")
    )


def credential_form_data():
    return {
        "site": request.form.get("site", "").strip(),
        "username": request.form.get("username", "").strip(),
        "password": request.form.get("password", ""),
    }