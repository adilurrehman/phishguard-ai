from functools import wraps

from flask import session, redirect


def login_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if 'user_id' not in session:
            return redirect('/login')

        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):

    @wraps(f)
    def decorated_function(*args, **kwargs):

        if 'user_id' not in session:
            return redirect('/login')

        if not session.get('is_admin'):
            return redirect('/')

        return f(*args, **kwargs)

    return decorated_function
