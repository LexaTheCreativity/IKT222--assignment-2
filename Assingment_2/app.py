import sqlite3
from flask_login import current_user, login_user, logout_user, login_required, UserMixin, LoginManager
from flask import Flask, render_template, redirect, url_for, request, session, flash, g
from database import connect_db
import hashlib
import os
# from flask_scrypt import generate_password_hash, check_password_hash, generate_random_salt
# from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for session management

DATABASE = 'database.db'

login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password


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
        return User(id=user[0], username=user[1], password=user[2])
    return None


@app.route('/')
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

def hash_password(password): # Hash password with salt
    salt = os.urandom(16)
    hashed_password = hashlib.sha256(salt + password.encode()).hexdigest()
    return salt.hex() + hashed_password


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Hash the password
        hashed_password = hash_password(password)

        conn = connect_db()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            flash('Registration successful! You can now log in.', category='success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different one.', category='error')
            return redirect(url_for('register'))
        except Exception as e:
            flash(f'An error occurred: {e}', category='error')
    else:
        return render_template('register.html')

def verify_password(stored_password, provided_password):
    salt = bytes.fromhex(stored_password[:32])
    stored_hash = stored_password[32:]
    provided_hash = hashlib.sha256(salt + provided_password.encode()).hexdigest()
    return provided_hash == stored_hash


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = connect_db()
        cursor = conn.cursor()

        # Fetches the user by username only
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        # Checks if user exists and verify the password
        if user is not None:
            stored_password = user[2]  # Get the stored hashed password
            if verify_password(stored_password, password):
                # Creates a user object if the password is correct
                user_obj = User(id=user[0], username=user[1], password=user[2])
                login_user(user_obj)
                session['user_id'] = user[0]
                flash('Login successful!', category='success')
                return redirect(url_for('home'))
            else:
                flash('Invalid username or password', category='error')
                return redirect(url_for('login'))
        else:
            flash('Invalid username or password', category='error')
            return redirect(url_for('login'))
    else:
        return render_template('login.html')


@app.route("/logout")
@login_required
def logout():
    if session['user_id']:
        logout_user()
        session.clear()
        flash("You were logged out. See you soon!")
        return redirect(url_for('home'))
    else:
        flash('Somwthing went wrong!', category='error')


@app.route('/add_post', methods=['GET', 'POST'])
@login_required
def add_post():
    if 'user_id' not in session:
        flash('You need to be logged in to add a post.', category='error')
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
                flash('An error occurred while adding your post. Please try again.')
        else:
            flash('You must login to add posts')
    else:
        flash('You must login to add posts')

    return render_template('add_post.html')


if __name__ == '__main__':
    app.run(debug=True)