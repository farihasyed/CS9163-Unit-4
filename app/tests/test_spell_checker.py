import pytest
from flask import escape
from spell_check import app

usernames = ['admin', 'farihasyed', 'uncchapelhill', 'dooksucks1', 'unc!', 'nyu12345', 'thisusernameislongerthan32characters']
passwords = ['Administrator@1', 'music922', 'unc', 'dook<sucks>', 'thispasswordislongerthan32characters']
phones = [12345678901, 9193089764, 1234567890123, 123, '0123456789', 'abc123']


@pytest.fixture
def client():
    app.app.config['TESTING'] = True
    app.app.config['WTF_CSRF_CHECK_DEFAULT'] = False
    app.app.config['WTF_CSRF_ENABLED'] = False
    with app.app.test_client() as client:
        with app.app.app_context():
            s = app.app
            c = app.app.app_context()
        yield client


def register(client, username, password, phone=''):
    return client.post('/register', data={'username': username, 'password': password, 'phone': phone},
                       follow_redirects=True)


def login(client, username, password='', phone=''):
    return client.post('/login', data={'username': username, 'password': password, 'phone': phone},
                       follow_redirects=True)


def spell_check(client, input):
    return client.post('/spell_check', data={'input': input}, follow_redirects=True)


def login_history(client, username):
    return client.post('/login_history', data={'username': username}, follow_redirects=True)


def user_query(client, username):
    return client.post('/history', data={'username': username}, follow_redirects=True)


def logout(client):
    return client.post('/logout', follow_redirects=True)


def test_register_get(client):
    response = client.get('/register')
    assert response.status_code == 200
    assert b"User Registration" in response.data


def test_register_post(client):
    # duplicate admin username
    response = register(client=client, username=usernames[0], password=passwords[0])
    assert b'Username already taken. Please choose another one.' in response.data

    # duplicate uppercase username
    response = register(client=client, username=usernames[1].upper(), password=passwords[1])
    assert b'Invalid username.' in response.data
    assert b'Only lowercase letters and numbers allowed.' in response.data

    # invalid username - not alphanumeric, too short
    response = register(client=client, username=usernames[4], password=passwords[1])
    assert b'Invalid username.' in response.data
    assert b'Only lowercase letters and numbers allowed.' in response.data
    assert b'Must be between 5 and 32 characters long.' in response.data

    # invalid username - too long
    response = register(client=client, username=usernames[6], password=passwords[0])
    assert b'Invalid username.' in response.data
    assert b'Must be between 5 and 32 characters long.' in response.data

    #invalid password - has other special characters
    response = register(client=client, username=usernames[1], password=passwords[3])
    assert b'Invalid password.' in response.data
    message = escape('Only letters, numbers, and the following special characters: _, @, #, %, and * allowed.').encode()
    assert message in response.data

    #invalid password - too long
    response = register(client=client, username=usernames[2], password=passwords[4])
    assert b'Invalid password.' in response.data
    assert b'Must be between 5 and 32 characters long.' in response.data

    #invalid phone - too long
    response = register(client=client, username=usernames[3], password=passwords[1], phone=phones[2])
    assert b'Invalid phone number' in response.data
    assert b'Only digits allowed and must be 10 digits long.' in response.data

    #invalid phone - too short
    response = register(client=client, username=usernames[3], password=passwords[1], phone=phones[3])
    assert b'Invalid phone number' in response.data
    assert b'Only digits allowed and must be 10 digits long.' in response.data

    #invalid phone - starts with a 0
    response = register(client=client, username=usernames[3], password=passwords[1], phone=phones[4])
    assert b'Invalid phone number' in response.data
    assert b'Only digits allowed and must be 10 digits long.' in response.data

    #invalid phone - alphanumeric
    response = register(client=client, username=usernames[3], password=passwords[1], phone=phones[5])
    assert b'Only digits allowed and must be 10 digits long.' in response.data


def test_login_get(client):
    response = client.get('/login')
    assert response.status_code == 200
    assert b'Sign in below or' in response.data
    assert b'for a new account' in response.data


def test_login_post_success(client):
    #correct username, password, phone
    response = login(client=client, username=usernames[0], phone=phones[0])
    logout(client)
    assert b'Success! You have been logged in.' in response.data
    assert b'Click' in response.data
    assert b'to access the spell checker.' in response.data

    #correct username and phone
    response = login(client=client, username=usernames[0], phone=phones[0])
    logout(client)
    assert b'Success! You have been logged in.' in response.data
    assert b'Click' in response.data
    assert b'to access the spell checker.' in response.data

    #correct username, phone, incorrect password
    response = login(client=client, username=usernames[1], password=passwords[1], phone=phones[1])
    logout(client)
    assert b'Success! You have been logged in.' in response.data
    assert b'Click' in response.data
    assert b'to access the spell checker.' in response.data


def test_login_post_failure(client):
    #nonregistered user
    response = login(client=client, username=usernames[5], password=passwords[1])
    logout(client)
    assert b'Incorrect username, password, and/or phone. Please try again.' in response.data

    #incorrect password
    response = login(client=client, username=usernames[0], password=passwords[1])
    logout(client)
    assert b'Incorrect username, password, and/or phone. Please try again.' in response.data

    #incorrect phone
    response = login(client=client, username=usernames[0], phone=phones[1])
    logout(client)
    assert b'Two-factor authentication failure.' in response.data


def test_spell_check_get_before_log_in(client):
    response = client.get('/spell_check', follow_redirects=True)
    assert b'You must be logged in to view this page.' in response.data


def test_history_get_before_log_in(client):
    response = client.get('/history', follow_redirects=True)
    assert b'You must be logged in to view this page.' in response.data


def test_login_history_get_before_log_in(client):
    response = client.get('/login_history', follow_redirects=True)
    assert b'You do not have permission to view this page.' in response.data
    login(client, username=usernames[1], password=passwords[1], phone=phones[1])
    response = client.get('/login_history', follow_redirects=True)
    logout(client)
    assert b'You do not have permission to view this page.' in response.data


def test_user_query_get_before_log_in(client):
    response = client.get('/history/farihasyed/query4', follow_redirects=True)
    assert b'You do not have permission to view this page.' in response.data
    login(client, username=usernames[1], password=passwords[1], phone=phones[1])
    response = client.get('/history/farihasyed/query4', follow_redirects=True)
    logout(client)
    assert b'You do not have permission to view this page.' in response.data


def test_spell_check_get_after_log_in(client):
    login(client, username=usernames[1], password=passwords[1], phone=phones[1])
    response = client.get('/spell_check', follow_redirects=True)
    logout(client)
    assert b'Spell Check' in response.data
    assert b'Enter text to be spell checked.' in response.data
    assert ('You are logged in as ' + usernames[0] + '.').encode()
    assert b'for a list of your queries.' in response.data


def test_history_after_log_in(client):
    login(client, username=usernames[1], password=passwords[1], phone=phones[1])
    response = client.get('/history', follow_redirects=True)
    logout(client)
    assert b'Query History' in response.data
    assert ('queries for ' + usernames[1]).encode()
    assert b'Query 3' in response.data
    assert b'Query 4' in response.data
    assert ('You are logged in as ' + usernames[1] + '.').encode()


def test_query_after_log_in(client):
    login(client, username=usernames[0], password=passwords[0], phone=phones[0])
    response = client.get('/history/query1', follow_redirects=True)
    logout(client)
    assert b'Query 1' in response.data
    assert ('User: ' + usernames[0]).encode() in response.data
    assert 'Input text: hello i am the admin'.encode() in response.data

    login(client, username=usernames[1], password=passwords[1], phone=phones[1])
    response = client.get('/history/query4', follow_redirects=True)
    logout(client)
    assert b'Query 4' in response.data
    assert ('User: ' + usernames[1]).encode() in response.data
    assert 'Input text: hello wrold!'.encode() in response.data
    assert b'wrold' in response.data


def test_login_history_get(client):
    login(client, username=usernames[0], password=passwords[0], phone=phones[0])
    response = client.get('/login_history', follow_redirects=True)
    logout(client)
    assert b'Login History' in response.data
    assert b'Username: ' in response.data


def test_login_history_post(client):
    login(client, username=usernames[0], password=passwords[0], phone=phones[0])
    response = login_history(client, usernames[1])
    assert b'Event 4' in response.data
    assert b'Login: 17:04:17' in response.data
    assert b'Logout: N/A' in response.data
    assert b'Event 6' in response.data
    assert b'Login: 17:17:34' in response.data
    assert b'Logout: 17:17:41' in response.data
    assert b'Event 8' in response.data
    assert b'Login: 18:05:50' in response.data
    assert b'Logout: 18:11:21' in response.data

    response = login_history(client, usernames[0])
    assert b'Event 1' in response.data
    assert b'Login: 16:55:12' in response.data
    assert b'Logout: 16:55:22' in response.data
    assert b'Event 2' in response.data
    assert b'Login: 16:56:27' in response.data
    assert b'Logout: 16:57:34' in response.data
    assert b'Event 3' in response.data
    assert b'Login: 16:57:41' in response.data
    assert b'Logout: N/A' in response.data
    logout(client)


def test_user_query_get_after_log_in(client):
    login(client, username=usernames[0], password=passwords[0], phone=phones[0])
    response = client.get('/history/farihasyed/query3', follow_redirects=True)
    logout(client)
    assert b'Query 3' in response.data
    assert ('User: ' + usernames[1]).encode() in response.data
    assert 'Input text: testing as myself so admin can look at my queries'.encode() in response.data
    assert b'qu' in response.data
    assert b'eries' in response.data


def test_user_query_post_after_log_in(client):
    login(client, username=usernames[0], password=passwords[0], phone=phones[0])
    response = user_query(client, usernames[1])
    logout(client)
    assert b'Query 3' in response.data
    assert b'Username:' in response.data


def test_spell_check_post(client):
    login(client, username=usernames[1], password=passwords[1], phone=phones[1])

    #valid input
    input = 'Take a sad sogn and make it better. Remember to let her under your skyn, then you begin to make it betta.'
    response = spell_check(client, input)
    assert b'Spell Check' in response.data
    assert b'Enter text to be spell checked.' in response.data
    assert ('You are logged in as ' + usernames[1] + '.').encode() in response.data
    assert ('Input text: ' + input).encode() in response.data
    assert b'sogn' in response.data
    assert b'skyn' in response.data
    assert b'betta' in response.data

    #escaped input
    input = '<>!@#$%!@#$'
    response = spell_check(client, input)
    assert b'Spell Check' in response.data
    assert b'Enter text to be spell checked.' in response.data
    assert ('You are logged in as ' + usernames[1] + '.').encode() in response.data
    assert b'&lt;&gt;!@#$%!@#$' in response.data
    assert b'lt;&gt' in response.data

    #invalid input
    input = '<><><><>>'
    response = spell_check(client, input)
    assert b'Spell Check' in response.data
    assert b'Enter text to be spell checked.' in response.data
    assert ('You are logged in as ' + usernames[1] + '.').encode() in response.data
    assert b'&lt;&gt;&lt;&gt;&lt;&gt;&lt;&gt;&gt;' in response.data

    #input too long
    input = "i'm trying to overflow the input buffer, which a hacker might do as part of a denial of service (DOS) attack, " \
            "but i'm a step ahead of them"
    response = spell_check(client, input)
    assert b'Spell Check' in response.data
    assert b'Enter text to be spell checked.' in response.data
    assert ('You are logged in as ' + usernames[1] + '.').encode() in response.data
    assert b'Input cannot be longer than 128 characters' in response.data
    logout(client)


def test_logout(client):
    response = logout(client)
    assert b'You have been logged out.' in response.data


