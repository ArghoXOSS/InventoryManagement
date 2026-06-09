from flask import session, redirect, url_for

def login_required(func):
    def wrapper(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return func(*args, **kwargs)

    wrapper.__name__ = func.__name__
    return wrapper