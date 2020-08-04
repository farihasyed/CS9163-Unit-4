import os
from flask import Flask, render_template, request, url_for, redirect, session, make_response
from flask_wtf import CSRFProtect
from forms import Registration, Login, SpellCheck, LoginHistory, QueryHistory
from spell_check import spell_check_user_input, register_with_user_info, verify_login, cleanup, PATH_PREFIX
from security import check_referrer, check_user, headers, admin_login_required, login_required, check_admin
from database import create_database, get_queries, get_logs, get_query


def create_app():
    app = Flask(__name__)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Strict')
    app.config.from_mapping(SECRET_KEY=os.environ['FLASK_KEY'])
    csrf = CSRFProtect()
    csrf.init_app(app)
    return app, csrf


app, csrf = create_app()
create_database()

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug='True')


@app.route('/')
def start():
    return redirect(url_for("login"))


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Login()
    if check_referrer() and form.validate_on_submit():
        username, password, phone = form.username.data, form.password.data, form.phone.data
        return verify_login(username, password, phone)
    response = make_response(render_template('login.html', form=form))
    response = headers(response)
    return response


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = Registration()
    if check_referrer() and form.validate_on_submit():
        username, password, phone = form.username.data, form.password.data, form.phone.data
        return register_with_user_info(username, password, phone)
    response = make_response(render_template('register.html', form=form))
    response = headers(response)
    return response


@app.route('/spell_check', methods=['GET', 'POST'])
@login_required
def spell_check():
    form = SpellCheck()
    if check_user() and form.validate_on_submit():
        file_path = PATH_PREFIX + "text/samples/file.txt"
        return spell_check_user_input(form.input.data, file_path)
    response = make_response(render_template('spell_check.html', user=session['user']['username'], form=form))
    response = headers(response)
    return response


@csrf.exempt
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        response = make_response(render_template('logout.html'))
        response = headers(response)
        cleanup()
        return response
    return redirect(url_for('login'))


@app.route('/history', methods=['GET', 'POST'])
@login_required
def history():
    if check_user():
        form = QueryHistory()
        username = session.get('user')['username']
        if check_admin():
            admin = True
            table, num_queries = get_queries(username)
            if form.validate_on_submit():
                username = form.username.data
                table, num_queries = get_queries(username, admin)
            response = make_response(render_template('history.html', table=table, num_queries=num_queries, form=form,
                                                     username=username, admin=admin))
        else:
            if request.method == 'GET':
                table, num_queries = get_queries(username)
                response = make_response(render_template('history.html', table=table, num_queries=num_queries,
                                                     username=username, form=form))
        response = headers(response)
        return response
    return redirect(url_for('login'))


@app.route('/history/query<int:id>', methods=['GET'])
@login_required
def query(id):
    if check_user():
        username = session.get('user')['username']
        query_id, username, query_text, query_result = get_query(username, id)
        response = make_response(render_template('query.html', query_id=query_id, username=username,
                                                 query_text=query_text, query_result=query_result))
        response = headers(response)
        return response
    return redirect(url_for('login'))


@app.route('/history/<username>/query<int:id>', methods=['GET', 'POST'])
@admin_login_required
def user_query_history(username, id):
    if check_user():
        query_id, username, query_text, query_result = get_query(username, id)
        response = make_response(render_template('query.html', query_id=query_id, username=username,
                                                 query_text=query_text, query_result=query_result))
        response = headers(response)
        return response
    return redirect(url_for('login'))


@app.route('/login_history', methods=['GET', 'POST'])
@admin_login_required
def login_history():
    form = LoginHistory()
    if check_admin() and form.validate_on_submit():
        username = form.username.data
        return get_logs(username)
    response = make_response(render_template('login_history.html', form=form))
    response = headers(response)
    return response



