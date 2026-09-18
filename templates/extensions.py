from functools import wraps

from flask import redirect, session, url_for


ACTIVE_KEYS = {}


def get_user_key():
    return ACTIVE_KEYS.get(session.get("session_id"))


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not get_user_key():
            return redirect(url_for("routes.login"))
        return view(*args, **kwargs)

    return wrapped_view


def init_extensions(app):
    @app.context_processor
    def template_helpers():
        return {"csrf_token": session.get("csrf_token", "")}