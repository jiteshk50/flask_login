from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, EqualTo
from email_validator import validate_email, EmailNotValidError
import os
from dotenv import load_dotenv
import sqlite3
from contextlib import closing
import secrets
import datetime
import smtplib
from email.mime.text import MIMEText

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your_secret_key')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False

# Database setup
DATABASE = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with closing(get_db_connection()) as conn:
        with open('schema.sql', 'r') as f:
            conn.cursor().executescript(f.read())
        conn.commit()

# Create database if it doesn't exist (Runs ONCE on app startup)
if not os.path.exists(DATABASE):
    init_db()

# Forms
class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class ForgotPasswordForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Reset Password')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

# Email configuration (store these in environment variables for security)
EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_SERVER = os.getenv("EMAIL_SERVER", "smtp.gmail.com")  # Default to gmail
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))  # Default to gmail port

def send_reset_email(email, token):
    reset_link = url_for('reset_password', token=token, _external=True)
    message = MIMEText(f"Click this link to reset your password: {reset_link}")
    message['Subject'] = "Password Reset Request"
    message['From'] = EMAIL_SENDER
    message['To'] = email

    try:
        with smtplib.SMTP(EMAIL_SERVER, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, email, message.as_string())
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data  # Moved this line here
        with closing(get_db_connection()) as conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user and user['password'] == password:
            session['email'] = email
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegistrationForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        with closing(get_db_connection()) as conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            if user:
                flash('Email already registered.', 'danger')
            else:
                try:
                    conn.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, password))
                    conn.commit()
                    flash('Registration successful! Please login.', 'success')
                    return redirect(url_for('login'))
                except sqlite3.IntegrityError:
                    flash('Email already registered.', 'danger')
    return render_template('signup.html', form=form)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        with closing(get_db_connection()) as conn:
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user:
            token = secrets.token_urlsafe(32)
            expiry_time = datetime.datetime.now() + datetime.timedelta(hours=1)
            with closing(get_db_connection()) as conn:
                try:
                    conn.execute('INSERT INTO password_reset_tokens (email, token, expiry_time) VALUES (?, ?, ?)', (email, token, expiry_time))
                    conn.commit()
                except sqlite3.IntegrityError:
                    conn.execute('UPDATE password_reset_tokens SET token = ?, expiry_time = ? WHERE email = ?', (token, expiry_time, email))
                    conn.commit()
            if send_reset_email(email, token):
                flash('A password reset link has been sent to your email.', 'info')
            else:
                flash('There was an error sending the reset email.', 'danger')
            return redirect(url_for('login'))
        else:
            flash('Email not found.', 'danger')
    return render_template('forgot_password.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    with closing(get_db_connection()) as conn:
        token_data = conn.execute('SELECT * FROM password_reset_tokens WHERE token = ?', (token,)).fetchone()
    if not token_data:
        flash("Invalid reset link.", "danger")
        return redirect(url_for('login'))

    expiry_time = datetime.datetime.fromisoformat(token_data['expiry_time'])
    if datetime.datetime.now() > expiry_time:
        flash("Reset link has expired.", "danger")
        with closing(get_db_connection()) as conn:
            conn.execute('DELETE FROM password_reset_tokens WHERE token = ?', (token,))
            conn.commit()
        return redirect(url_for('login'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        password = form.password.data
        with closing(get_db_connection()) as conn:
            conn.execute('UPDATE users SET password = ? WHERE email = ?', (password, token_data['email']))
            conn.execute('DELETE FROM password_reset_tokens WHERE token = ?', (token,))
            conn.commit()
        flash('Your password has been reset.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form, email=token_data['email'])

@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        return render_template('dashboard.html', email=session['email'])
    else:
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('email', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)