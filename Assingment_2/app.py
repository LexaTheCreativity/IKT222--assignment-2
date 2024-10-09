import sqlite3
from flask_login import current_user, login_user, logout_user, login_required, UserMixin, LoginManager
from flask import Flask, render_template, redirect, url_for, request, session, flash, g
from database import connect_db
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


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # salt = generate_random_salt()
        # hashed_password = generate_password_hash(password)

        conn = connect_db()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
            flash('Registration successful! You can now log in.', category='success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different one.', category='error')
        except Exception as e:
            flash(f'An error occurred: {e}', category='error')
    else:
        return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = connect_db()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()

        if user and user[2] == password:
            session['user_id'] = user[0]
            flash('Login successful!', category='success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', category='error')
            return redirect(url_for('login'))
    else:
        return render_template('login.html')


@app.route("/logout")
@login_required
def logout():
    session.clear()
    logout_user()
    flash("You were logged out. See you soon!")
    return redirect(url_for('home.html'))


@app.route('/add_post', methods=['GET', 'POST'])
@login_required
def add_post():
    if 'user_id' not in session:
        flash('You need to be logged in to add a post.', category='error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']

        if current_user.is_authenticated:
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