import sqlite3
# import limiter
from flask_login import current_user, login_user, logout_user, login_required, UserMixin, LoginManager
from flask import Flask, render_template, redirect, url_for, request, session, flash, g
from unicodedata import category
from database import connect_db
import hashlib
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp
import qrcode
from io import BytesIO
from base64 import b64encode
import base64
import time
import datetime


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for session management

DATABASE = 'database.db'

login_manager = LoginManager()
login_manager.init_app(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["2 per minute", "1 per second"],
    storage_uri="memory://",
    strategy="fixed-window", # or "moving-window"
)

class User(UserMixin):
    def __init__(self, id, username, password, totp_secret):
        self.id = id
        self.username = username
        self.password = password
        self.totp_secret = totp_secret


@login_manager.user_loader
def load_user(user_id):
    # Fetch user from the database using the user_id
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user:
        # Return the user object with the retrieved data
        return User(id=user[0], username=user[1], password=user[2], totp_secret=user[3])
    return None


@app.route('/')
@limiter.limit("10 per minute")  # Adjust the rate limit as needed
def home():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT posts.title, posts.content, users.username 
        FROM posts 
        JOIN users ON posts.user_id = users.id
    """)
    posts = cursor.fetchall()
    conn.close()

    return render_template('home.html', posts=posts)

def hash_password(password):
    # Generate a random salt
    salt = os.urandom(16)
    # Hash the password with the salt
    hashed_password = hashlib.sha256(salt + password.encode()).hexdigest()
    # Return a string combining the salt and hashed password with a delimiter
    return salt.hex() + ":" + hashed_password

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Adjust the rate limit as needed
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Generate hashed password with salt
        hashed_password = hash_password(password)
        print(f"Hashed password being stored: {hashed_password}")  # Debugging output

        conn = connect_db()
        cursor = conn.cursor()

        # Check if the username already exists in the database
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user != None:
            flash('Username already exists. Please choose a different one.', category='danger')
            return redirect(url_for('register'))
        else:
            try:
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
                conn.commit()
                flash("You are registered. You have to enable 2-Factor Authentication first to login.", category="success")

                return redirect(url_for('setup2fa', username=username))

            except Exception as e:
                flash(f'An error occurred: {e}', category='danger')
                return render_template('register.html')
    else:
        return render_template('register.html')




def verify_password(stored_password, provided_password):
    # Check that stored_password contains a colon
    if ':' not in stored_password:
        raise ValueError("Stored password format is invalid, missing salt delimiter ':'.")

    # Split stored_password into salt and hash
    salt_hex, stored_hash = stored_password.split(":")

    # Convert the hex salt back to bytes
    salt = bytes.fromhex(salt_hex)

    # Hash the provided password with the extracted salt
    provided_hash = hashlib.sha256(salt + provided_password.encode()).hexdigest()

    # Compare the hashes
    return provided_hash == stored_hash


def too_many_attempts(username):
    conn = connect_db()
    cursor = conn.cursor()

    # Count failed attempts within the last 5 minutes
    cursor.execute('''
        SELECT COUNT(*) FROM login_attempts
        WHERE username = ? AND attempt_time >= datetime('now', '-5 minutes')
    ''', (username,))
    attempt_count = cursor.fetchone()[0]
    conn.close()

    # Return True if there are 3 or more attempts in the last 5 minutes
    return attempt_count >= 3


def record_failed_attempt(username):
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO login_attempts (username) VALUES (?)", (username,))
    conn.commit()
    conn.close()


@app.route('/setup2fa/<username>', methods=['GET', 'POST'])
def setup2fa(username):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user is not None:
        secret = pyotp.random_base32()

        cursor.execute("UPDATE users SET totp_secret = ? WHERE username = ?", (secret,username))
        conn.commit()

        # Generate TOTP provisioning URI
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username, issuer_name="Secret app")

        # Generate the QR code image
        qr_image = qrcode.make(uri)
        buffered = BytesIO()
        qr_image.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

        # print(f"QR Base64 data: {qr_base64[:50]}...")  # Print a snippet of the data

        return render_template('setup2fa.html', username=username, qr_base64=qr_base64)
    else:
        flash('User not found.', category='danger')
        return redirect(url_for('register'))


@app.route('/verify2fa/<username>', methods=['GET', 'POST'])
def verify2fa(username):
    if request.method == 'POST':
        otp_input = request.form['otp_input']

        print(otp_input)
        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        print(user)

        try:
            if user is not None:
                #cursor.execute("UPDATE users SET totp_secret = ? WHERE username = ?", (username,))
                #conn.commit()

                totp_secret = user[3]

                totp = pyotp.TOTP(totp_secret)

                if totp.verify(otp_input):
                    flash("2FA verification successful", category="success")
                    return redirect(url_for('home'))
                else:
                    flash("Invalid 2FA OTP, please try again.", category="danger")
                    return redirect(url_for('verify2fa', username=username))
            else:
                flash('User not found.', category='danger')
                return redirect(url_for('register'))
        finally:
            conn.close()
    else:
        return render_template("verify2fa.html", username=username)



@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Adjust the rate limit as needed
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the user has too many failed login attempts
        if too_many_attempts(username):
            flash("Too many failed attempts. Please try again after 5 minutes.", category='danger')
            return redirect(url_for('login'))

        conn = connect_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        # Check if user exists and print the retrieved password for debugging
        if user is not None:
            stored_password = user[2]  # Get the stored hashed password
            if verify_password(stored_password, password):
                # Clear any failed attempts upon successful login
                conn = connect_db()
                cursor = conn.cursor()
                cursor.execute("DELETE FROM login_attempts WHERE username = ?", (username,))
                conn.commit()
                conn.close()

                # Create a user object if the password is correct
                user_obj = User(id=user[0], username=user[1], password=user[2], totp_secret=user[3])
                #verify2fa(user_obj.username)
                login_user(user_obj)
                session['user_id'] = user[0]
                flash('Login successful!', category='success')
                return redirect(url_for('verify2fa', username=username))
            else:
                record_failed_attempt(username)
                flash('Invalid username or password', category='danger')
                return redirect(url_for('login'))
        else:
            record_failed_attempt(username)
            flash('Invalid username or password', category='danger')
            return redirect(url_for('login'))
    else:
        return render_template('login.html')


@app.route("/logout")
@limiter.limit("10 per minute")  # Adjust the rate limit as needed
@login_required
def logout():
    if session['user_id']:
        logout_user()
        session.clear()
        flash("You were logged out. See you soon!", category='success')
        return redirect(url_for('home'))
    else:
        flash('Somwthing went wrong!', category='danger')


@app.route('/add_post', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Adjust the rate limit as needed
@login_required
def add_post():
    if 'user_id' not in session:
        flash('You need to be logged in to add a post.', category='danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        if session['user_id'] != None:
            try:
                conn = connect_db()
                cursor = conn.cursor()
                cursor.execute("INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)",
                               (title, content, session['user_id']))
                conn.commit()

                flash('Post added successfully!', category='success')
                return redirect(url_for('home'))

            except Exception as e:
                print(f"error while adding post: {e}")
                flash('An error occurred while adding your post. Please try again.', category='danger')
        else:
            flash('You must login to add posts', category='danger')
    else:
        flash('You must login to add posts', category='danger')

    return render_template('add_post.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
