import sqlite3
from flask import request, session, url_for, flash, redirect
from secrets import token_hex
from sqlite3 import Error
from datetime import datetime
from cryptography.fernet import Fernet
import random
import string
import hashlib
import binascii
import os
from tables import QueryTable
from glob import glob

SECRET_PATH = "/run/secrets/"
SECRETS = ['database_path', 'admin_username', 'admin_phone', 'admin_password', 'flask_key', 'key']
TOKEN_BYTES = 32
ITERATIONS = 100000
SALT_SIZE = 32
HASHING_ALGOS = [hashlib.sha256(), hashlib.sha384(), hashlib.md5()]
PEPPERS = list(string.ascii_uppercase)
QUERY_URL_PREFIX = 'history/query'


def set_environment_variables():
    for secret in glob(SECRET_PATH + "*"):
        secret = secret.split('/')[-1]
        file = open(SECRET_PATH + secret)
        os.environ[secret.upper()] = file.read()
        file.close()


set_environment_variables()
DATABASE = os.environ['DATABASE_PATH']
ADMIN_USERNAME = os.environ['ADMIN_USERNAME']
ADMIN_PASSWORD = os.environ['ADMIN_PASSWORD']
ADMIN_PHONE = os.environ['ADMIN_PHONE']
KEY = os.environ['KEY']


def get_connection():
    connection = sqlite3.connect(DATABASE)
    cursor = connection.cursor()
    return connection, cursor


def close_database(connection):
    if connection:
        connection.commit()
        connection.close()


def create_database():
    connection = None
    try:
        connection, cursor = get_connection()
        with connection:
            cursor.execute("""CREATE TABLE IF NOT EXISTS credentials (
                            username VARCHAR(32) NOT NULL PRIMARY KEY UNIQUE, 
                            password TEXT NOT NULL, 
                            phone TEXT)
                            """)
            cursor.execute("""CREATE TABLE IF NOT EXISTS hashed (
                            password TEXT NOT NULL,
                            hash TEXT NOT NULL,
                            salt TEXT NOT NULL,
                            FOREIGN KEY (password) REFERENCES credentials (password))
                            """)
            cursor.execute("""CREATE TABLE IF NOT EXISTS queries (
                            query_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username VARCHAR(32) NOT NULL, 
                            input VARCHAR(128), 
                            output VARCHAR(128),
                            FOREIGN KEY (username) REFERENCES credentials (username))
                            """)
            cursor.execute("""CREATE TABLE IF NOT EXISTS logs (
                            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username VARCHAR(32) NOT NULL, 
                            login VARCHAR(10),
                            logout VARCHAR(10),
                            FOREIGN KEY (username) REFERENCES credentials (username))
                            """)
            cursor.execute("""CREATE TABLE IF NOT EXISTS sessions (
                            username VARCHAR(32) NOT NULL, 
                            session_token TEXT NOT NULL,
                            remote_address VARCHAR(12) NOT NULL,
                            login VARCHAR(10) NOT NULL,
                            FOREIGN KEY (username) REFERENCES credentials (username))
                            """)
            hashed_password, hash_name, salt = hash_password(ADMIN_PASSWORD)
            cursor.execute("INSERT OR REPLACE INTO credentials (username, password, phone) values (?, ?, ?)",
                           [ADMIN_USERNAME, hashed_password, encrypt_phone(ADMIN_PHONE)])
            cursor.execute("INSERT OR REPLACE INTO hashed (password, hash, salt) values (?, ?, ?)",
                           [hashed_password, hash_name, salt])
            cursor.execute("SELECT * FROM credentials")
    except Error as e:
        error_handling(e)
    finally:
        close_database(connection)


def error_handling(error):
    print(error)
    return False


def get_token_and_address(user):
    connection = None
    try:
        connection, cursor = get_connection()
        with connection:
            cursor.execute("SELECT session_token, remote_address FROM sessions WHERE username = ?",
                           [user['username']])
            rows = cursor.fetchall()
            session_token = None
            remote_address = None
            if rows is not None and len(rows) != 0:
                session_token = rows[len(rows) - 1][0]
                remote_address = rows[len(rows) - 1][1]
            return session_token, remote_address
    except Error as e:
        error_handling(e)
    finally:
        close_database(connection)


def login_db(username, password, phone):
    failure = 'Incorrect username, password, and/or phone. Please try again.'
    connection = None
    try:
        connection, cursor = get_connection()
        with connection:
            cursor.execute("SELECT * FROM credentials WHERE username = ?", [username])
            credential = cursor.fetchone()
            if credential is not None and len(credential) > 0:
                password_db = credential[1]
                phone_db = credential[2]
                if len(password) != 0:
                    cursor.execute("SELECT hash, salt FROM hashed WHERE password = ?", [password_db])
                    result = cursor.fetchone()
                    hash_name = result[0]
                    salt = result[1]
                    if verify_password(password_db, password, hash_name, salt):
                        return successful_login(username, cursor)
                elif len(str(phone)) != 0:
                    decrypted_phone = decrypt_phone(phone_db)
                    if phone != decrypted_phone:
                        failure = 'Two-factor authentication failure.'
                    else:
                        return successful_login(username, cursor)
        flash(failure, 'failure')
        return False
    except Error as e:
        error_handling(e)
    finally:
        close_database(connection)


def successful_login(username, cursor):
    session.clear()
    remote_address = request.remote_addr
    time = datetime.now().strftime("%H:%M:%S")
    cursor.execute("INSERT INTO logs (username, login) values (?, ?)", [username, time])
    token = str(token_hex(TOKEN_BYTES))
    session['user'] = {'username': str(username), 'session_token': token, 'remote address': remote_address,
                       'login': time}
    cursor.execute("""INSERT INTO sessions (username, session_token, remote_address, login) 
                                    values (?, ?, ?, ?)""", [username, token, remote_address, time])
    return True


def register_db(username, password, phone):
    connection = None
    try:
        connection, cursor = get_connection()
        with connection:
            cursor.execute("SELECT * FROM credentials WHERE username = ?", [username])
            if cursor.rowcount <= 0:
                hashed_password, hash_name, salt = hash_password(password)
                encrypted_phone = encrypt_phone(phone)
                cursor.execute("INSERT INTO credentials (username, password, phone) values (?, ?, ?)",
                               [username, hashed_password, encrypted_phone])
                cursor.execute("INSERT INTO hashed (password, hash, salt) values (?, ?, ?)",
                               [hashed_password, hash_name, salt])
                return True
            else:
                failure = 'Username already taken. Please choose another one.'
                flash(failure, 'failure')
        return False
    except Error as e:
        error_handling(e)
    finally:
        close_database(connection)


def hash_password(password):
    hash_algo = HASHING_ALGOS[random.randint(0, len(HASHING_ALGOS) - 1)]
    hash_name = hash_algo.name
    hash_algo.update(os.urandom(SALT_SIZE))
    salt = hash_algo.hexdigest().encode('ascii')
    pepper = PEPPERS[random.randint(0, len(PEPPERS) - 1)]
    peppered_password = password + pepper
    password_hash = hashlib.pbkdf2_hmac(hash_name, peppered_password.encode('utf-8'), salt, ITERATIONS)
    password_hash = binascii.hexlify(password_hash)
    salted_and_peppered_password_hash = salt + password_hash
    hashed_password = salted_and_peppered_password_hash.decode('ascii')
    return hashed_password, hash_name, salt


def verify_password(password_db, password, hash_name, salt):
    for pepper in PEPPERS:
        peppered_password = password + pepper
        password_hash = hashlib.pbkdf2_hmac(hash_name, peppered_password.encode('utf-8'), salt, ITERATIONS)
        password_hash = binascii.hexlify(password_hash)
        salted_and_peppered_password_hash = salt + password_hash
        password_hash = salted_and_peppered_password_hash.decode('ascii')
        if password_db == password_hash:
            return True
    return False


def encrypt_phone(phone):
    f = Fernet(KEY.encode('utf-8'))
    return f.encrypt(str(phone).encode('utf-8'))


def decrypt_phone(phone):
    f = Fernet(KEY.encode('utf-8'))
    return int(f.decrypt(phone).decode('utf-8'))


def spell_check_db(input, output):
    try:
        connection, cursor = get_connection()
        with connection:
            username = session.get('user')['username']
            cursor.execute("INSERT INTO queries (username, input, output) values (?, ?, ?)", [username, input, output])
        return True
    except Error as e:
        error_handling(e)
    finally:
        close_database(connection)


def cleanup_db(user):
    try:
        connection, cursor = get_connection()
        with connection:
            username = user['username']
            session_token = user['session_token']
            login = user['login']
            logout = datetime.now().strftime("%H:%M:%S")
            cursor.execute("UPDATE logs SET logout = ? WHERE username = ? AND login = ?", [logout, username, login])
            cursor.execute("DELETE FROM sessions WHERE username = ? and session_token = ?", [username, session_token])
            return True
    except Error as e:
        error_handling(e)
    finally:
        close_database(connection)


def get_queries(username, admin=False):
    try:
        connection, cursor = get_connection()
        with connection:
            cursor.execute("SELECT query_id FROM queries WHERE username = ?", [username])
            rows = cursor.fetchall()
            queries = [process_query_history(row, username, admin) for row in rows]
            return QueryTable(queries), len(queries)
    except Error as e:
        error_handling(e)
    finally:
        close_database(connection)


def process_query_history(row, username, admin):
    query_id = row[0]
    if admin:
        query_url = url_for('user_query_history', username=username, id=query_id)
    else:
        query_url = url_for('query', id=query_id)
    query = {'query_id': ' '.join(['Query', str(query_id)]), 'query_url': query_url, 'id': 'query' + str(query_id)}
    return query


def get_query(username, id):
    connection = None
    try:
        connection, cursor = get_connection()
        with connection:
            cursor.execute("SELECT * FROM queries WHERE username = ? AND query_id = ?", [username, id])
            row = cursor.fetchone()
            query_id, username, query_text, query_result = None, None, None, None
            if row is not None:
                query_id, username, query_text, query_result = row[0], row[1], row[2], row[3]
            return query_id, username, query_text, query_result
    except Error as e:
        error_handling(e)
    finally:
        close_database(connection)


def get_logs(username):
    connection = None
    try:
        connection, cursor = get_connection()
        with connection:
            cursor.execute("SELECT event_id, login, logout FROM logs WHERE username = ?", [username])
            rows = cursor.fetchall()
            events = [process_log(row) for row in rows]
            return flash_logs(events)
    except Error as e:
        error_handling(e)
    finally:
        close_database(connection)


def flash_logs(events):
    for event in events:
        id_tags = [event[0], event[0], event[0]]
        event.extend(id_tags)
        flash(event)
    return redirect(url_for('login_history'))


def process_log(row):
    event = row[0]
    login = row[1]
    logout = row[2] if row[2] is not None else 'N/A'
    return [event, login, logout]
