# database.py
import sqlite3

def connect_db():
    conn = sqlite3.connect('blog.db')
    return conn

def create_tables():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL  -- Increase size if needed for hash and salt
        )
    ''')
    conn.commit()
    conn.close()

if __name__ == '__main__':
    create_tables()
