from flask_login import current_user, login_user, logout_user, login_required, UserMixin, LoginManager
from flask import Flask, render_template, redirect, url_for, request, session, flash, g
from database import connect_db
from werkzeug.security import generate_password_hash, check_password_hash

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
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method='sha256')

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (email, username, password) VALUES (?, ?)", (email, username, hashed_password))
        conn.commit()

        return redirect(url_for('login'))
    return render_template('register.html', title='Register')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        conn = connect_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE (email, password) = (?,?)", (email, password))
        user = cursor.fetchone()

        if user and check_password_hash(user[2], password):
            user_obj = user(id=user[0], username=user[1], password=user[2])
            login_user(user_obj)  # Logs the user in
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', category='error')
            return "Invalid credentials"

    return render_template('login.html', title='Login')


@login_required
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home.html'))


@app.route('/add_post', methods=['GET', 'POST'])
@login_required
def add_post():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        try:
            conn = connect_db()
            cursor = conn.cursor()
            cursor.execute("INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)",
                           (title, content, current_user.id))
            conn.commit()

            return redirect(url_for('home'))

        except Exception as e:
            print(f"error while adding post: {e}")
            flash('An error occurred while adding your post. Please try again.')

    return render_template('add_post.html')


if __name__ == '__main__':
    app.run(debug=True)