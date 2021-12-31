from flask import Flask, session, render_template, request, redirect, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt  
import re

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key="Sex"
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route('/')
def index():
    flash("You have just logged out", "logout")
    session.clear()
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    session['first_name'] = request.form['first_name']
    session['last_name'] = request.form['last_name']
    session['email'] = request.form['email']
    pw_hash = None
    if len(request.form['password']) > 1: pw_hash = bcrypt.generate_password_hash(request.form['password']) 

    validate_first_name()
    validate_last_name()
    validate_email()
    pw_hash = validate_password(pw_hash)
    validate_confirm_password()
    return create_new_user(pw_hash)

def validate_first_name():
    if len(request.form['first_name']) < 1:
        flash("First name cannot be empty", "first_name")
        session.pop('first_name')
    elif len(request.form['first_name']) < 2:
        flash("First name must contain more than one letter", "first_name")
        session.pop('first_name')
    else:
        for s in request.form['first_name']:
            if not s.isalpha() and s!='-':
                flash("First name must only include letters or '-'", "first_name")
                session.pop('first_name')
                break

def validate_last_name():
    if len(request.form['last_name']) < 1:
        flash("Last name cannot be empty", "last_name")
        session.pop('last_name')
    elif len(request.form['last_name']) < 2:
        flash("Last name must contain more than one letter", "last_name")
        session.pop('first_name')
    else:
        for s in request.form['last_name']:
            if not s.isalpha() and s!='-':
                flash("Last name must only include letters or '-'", "last_name")
                session.pop('last_name')
                break

def validate_email():
    if len(request.form['email']) < 1:
        flash("Email cannot be empty!", "email")
        session.pop('email')
    elif not EMAIL_REGEX.match(request.form['email']):
        flash('Invalid email address', "email")
        session.pop('email')
    if 'email' in session:
        mysql = connectToMySQL('messengerdb')
        query = "select email from users where users.email = %(email)s;"
        data = {
            'email': session['email']
        }
        emails = mysql.query_db(query, data)
        if len(emails) > 0: 
            flash('Email address already exists', "email")
            session.pop('email')

def validate_password(pw_hash: str) -> str:
    if len(request.form['password']) < 1:
        flash("Password cannot be empty", "password")
        pw_hash = None
    elif len(request.form['password']) < 9:
        flash("Password must contain more than 8 characters", "password")
        pw_hash = None
    else:
        up = False
        num = False
        for s in request.form['password']:
            if s.isupper(): up = True
            if s.isdigit(): num = True
        if not up:
            flash("Password must contain at least one uppercase letter", "password")
            pw_hash = None
        elif not num:
            flash("Password must contain at least one numerical value", "password")
            pw_hash = None
    return pw_hash

def validate_confirm_password():
    if len(request.form['confirm_password']) < 1:
        flash("Confirm password cannot be empty!", "confirm_password")
    elif request.form['confirm_password'] != request.form['password']: 
        flash("Confirm password is not the same as password", "confirm_password")

def create_new_user(pw_hash) -> redirect:
    if ('first_name' in session) and ('last_name' in session) and ('email' in session) and pw_hash != None:
        mysql = connectToMySQL('messengerdb')
        query = "insert into users (first_name, last_name, email, password, created_at, updated_at) values (%(first_name)s, %(last_name)s, %(email)s, %(password)s, NOW(), NOW());"
        data = {
            'first_name': session['first_name'],
            'last_name': session['last_name'],
            'email': session['email'],
            'password': pw_hash
        }
        new_user_id = mysql.query_db(query, data)
        session['user_id'] = new_user_id
        return redirect('/success')
    else: return redirect('/')

@app.route('/success')
def success():
    received_messages = get_received_messages()
    sent_count = get_sent_messages()
    result = get_other_users()
    return render_template('success.html', other_users = result, messages_number = len(received_messages), total_messages_sent = sent_count[0][0], messages_for = received_messages)

def get_received_messages() -> tuple:
    mysql = connectToMySQL('messengerdb')
    query = "select * from messages where receiver_id = %(user_id)s order by created_at desc;"
    data = {
        'user_id': session['user_id']
    }
    return mysql.query_db(query, data) 

def get_sent_messages() -> tuple:
    mysql = connectToMySQL('messengerdb')
    query = "select count(message) from messages where sender_id = %(user_id)s;"
    data = {
        'user_id': session['user_id']
    }
    return mysql.query_db(query, data)

def get_other_users() -> tuple:
    mysql = connectToMySQL('messengerdb')
    query = "select * from users where not users.id = %(user_id)s;"
    data = {
        'user_id': session['user_id']
    }
    return mysql.query_db(query, data)

@app.route('/login', methods=['POST'])
def login():
    session['email'] = request.form['email']
    mysql = connectToMySQL('messengerdb')
    query = "select * from users where users.email = %(email)s;"
    data = {
        'email': session['email']
    }
    result = mysql.query_db(query, data)
    if result:
        if bcrypt.check_password_hash(result[0][4], request.form['password']):
            session['user_id'] = result[0][0]
            session['first_name'] = result[0][1]
            session['last_name'] = result[0][2]
            session['email'] = result[0][3]
            flash("You have logged in successfully", "success")
            return redirect('/success')
        else: 
            flash("Incorect password", "login_password")
            return redirect('/')
    else:
        flash("Incorrect email", "login_email")
        return redirect('/')

@app.route('/send_message/<x>', methods=['POST'])
def send_message(x):
    mysql = connectToMySQL('messengerdb')
    query = "insert into messages (message, sender_id, receiver_id, created_at, updated_at) values(%(message)s, %(sender_id)s, %(receiver_id)s, NOW(), NOW());"
    data = {
        'message': request.form.get('message_textarea'),
        'sender_id': session['user_id'],
        'receiver_id': x
    }
    new_message_id = mysql.query_db(query, data)
    return redirect('/success')

@app.route('/delete/<x>', methods=['POST'])
def delete(x):
    mysql = connectToMySQL('messengerdb')
    query = "delete from messages where id = {0};".format(x)
    return redirect('/success')

if __name__=="__main__":
    app.run(debug=True)