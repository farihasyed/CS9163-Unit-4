from flask import url_for, redirect, session, flash
import subprocess
from subprocess import Popen
import bleach
from database import login_db, register_db, spell_check_db, cleanup_db

PATH_PREFIX = "app/"


def verify_login(username, password, phone):
    cleanup()
    login_result = login_db(username, password, phone)
    if login_result:
        success = 'Success! You have been logged in.'
        flash(success, 'success')
    return redirect(url_for('login'))


def register_with_user_info(username, password, phone):
    registration_result = register_db(username, password, phone)
    if registration_result:
        success = 'Success! You have been registered.'
        flash(success, 'success')
    return redirect(url_for('register'))


def clean(input):
    return bleach.clean(input)


def spell_check_user_input(input, file_path):
    input = clean(input)
    file = open(file_path, "w")
    file.write(clean(input))
    file.close()
    input = 'Input text: ' + input
    process = Popen([PATH_PREFIX + "a.out", file_path, PATH_PREFIX + "text/wordlist.txt"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    universal_newlines=True)
    output, errors = process.communicate()
    if len(output) == 0:
        output = 'Could not spell check invalid input.'
    spell_check_db(input, output)
    flash(output, 'output')
    flash(input, 'input')
    return redirect(url_for('spell_check'))


def cleanup():
    if 'user' in session:
        user = session.get("user")
        cleanup_db(user)
        session.pop('user')