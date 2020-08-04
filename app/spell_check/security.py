from flask import session, request, flash, redirect, url_for
from database import get_token_and_address, ADMIN_USERNAME
import functools

service_referrer = ['login', 'spell_check', 'register', 'login_history', 'query', 'history', 'user_query_history']


def admin_login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not check_admin():
            flash("You do not have permission to view this page.", 'failure')
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        user = session.get('user')
        if user is None:
            flash("You must be logged in to view this page.", 'failure')
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view


def headers(response):
    jquery = 'https://code.jquery.com'
    popper = 'https://cdn.jsdelivr.net'
    bootstrap = 'https://stackpath.bootstrapcdn.com'
    separator = ' '
    csp_allowed = separator.join([jquery, popper, bootstrap])
    response.headers['Content-Security-Policy'] = "default-src 'self' script-src 'self' " + csp_allowed + "style-src " + csp_allowed
    response.headers['Strict-Transport-Security'] = 'max-age=3600; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '0'
    return response


def check_user():
    user = session.get('user')
    if user is not None:
        expected_session_token, expected_remote_address = get_token_and_address(user)
        return user['remote address'] == expected_remote_address and \
            user['session_token'] == expected_session_token and check_referrer() and check_origin()
    return False


def check_referrer():
    service = request.endpoint
    referrer = request.referrer
    if service in service_referrer:
        if referrer is None:
            return True
        for ref in service_referrer:
            if referrer.find(ref) != -1:
                return True
    return False


def check_origin():
    origin = None
    user = session.get('user')
    if user is not None:
        if request is not None and len(request.data) != 0 and request.data.find('origin') != -1:
            origin = request.origin
            expected_session_token, expected_remote_address = get_token_and_address(user)
            return str(origin).find(expected_remote_address) != -1
        return origin is None
    return False


def check_admin():
    user = session.get('user')
    if user is not None:
        expected_session_token, expected_remote_address = get_token_and_address(user)
        return user['username'] == ADMIN_USERNAME and user['session_token'] == expected_session_token \
               and user['remote address'] == expected_remote_address
    return False

