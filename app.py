from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length, Regexp
import sqlite3
import os
from datetime import timedelta
import time
import logging

app = Flask(__name__)
app.secret_key = os.urandom(32)

# CSRF Protection
csrf = CSRFProtect(app)

# Session Security
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15)
)

# Logging (Extra Security Feature)
logging.basicConfig(filename='security.log', level=logging.WARNING)

# Rate Limiting
login_attempts = {}

# DB Helper
def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

# ---------------- FORMS ----------------
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3)])
    
    # 🔐 Strong Password Policy (EXTRA SECURITY)
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6),
        Regexp(r'^(?=.*[A-Z])(?=.*\d).+$', 
        message="Must contain 1 capital letter and 1 number")
    ])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class TodoForm(FlaskForm):
    task = StringField('Task', validators=[DataRequired(), Length(min=1)])

# ---------------- SECURITY HEADERS ----------------
@app.after_request
def headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Content-Security-Policy'] = "default-src 'self' https://cdn.jsdelivr.net"
    return response

# ---------------- ROUTES ----------------
@app.route('/')
def home():
    return render_template('index.html')

# REGISTER
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = generate_password_hash(form.password.data)

        db = get_db()
        try:
            db.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            db.commit()
        except:
            return "User already exists"

        return redirect(url_for('login'))

    return render_template('register.html', form=form)

# LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    ip = request.remote_addr

    if ip in login_attempts:
        attempts, last = login_attempts[ip]
        if attempts >= 5 and time.time() - last < 60:
            return "Too many attempts"

    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user'] = username
            session['user_id'] = user['id']
            session.permanent = True

            login_attempts[ip] = (0, time.time())
            return redirect(url_for('dashboard'))

        else:
            logging.warning(f"Failed login from {ip}")
            login_attempts[ip] = (login_attempts.get(ip, (0,0))[0] + 1, time.time())
            return "Invalid credentials"

    return render_template('login.html', form=form)

# DASHBOARD (Todo)
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))

    form = TodoForm()
    db = get_db()

    # Add Task
    if form.validate_on_submit():
        db.execute("INSERT INTO todos (user_id, task) VALUES (?, ?)", 
                   (session['user_id'], form.task.data))
        db.commit()

    # Show Only User Tasks
    tasks = db.execute("SELECT * FROM todos WHERE user_id=?", 
                       (session['user_id'],)).fetchall()

    return render_template('dashboard.html', form=form, tasks=tasks)

# DELETE TASK
@app.route('/delete/<int:id>')
def delete(id):
    if 'user' not in session:
        return redirect(url_for('login'))

    db = get_db()

    # 🔐 Prevent deleting others' tasks
    db.execute("DELETE FROM todos WHERE id=? AND user_id=?", 
               (id, session['user_id']))
    db.commit()

    return redirect(url_for('dashboard'))

# LOGOUT
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# RUN
if __name__ == '__main__':
    app.run(debug=True)