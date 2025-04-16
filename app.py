from flask import Flask, render_template, request, redirect, session, url_for
import psycopg2
from config import DATABASE_URL

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ----------------------------------------------------------------
# Automatically create tables on app start
def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    # Create 'users' table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) NOT NULL UNIQUE,
        password VARCHAR(100) NOT NULL,
        full_name VARCHAR(200),
        company_name VARCHAR(200),
        business_id VARCHAR(100),
        is_admin BOOLEAN DEFAULT FALSE
    );
    """)

    # Create 'selected_agents' table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS selected_agents (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        name VARCHAR(200),
        category VARCHAR(100),
        package VARCHAR(100),
        status VARCHAR(50)
    );
    """)

    conn.commit()
    conn.close()

# ----------------------------------------------------------------
# Function to get a new database connection.
def get_db():
    return psycopg2.connect(DATABASE_URL)

# ----------------------------------------------------------------
# Welcome screen with user/admin choice
@app.route('/')
def home():
    return render_template('welcome.html')

# ----------------------------------------------------------------
# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=%s AND password=%s",
                    (request.form['username'], request.form['password']))
        user = cur.fetchone()
        conn.close()
        if user:
            session['user_id'] = user[0]
            session['full_name'] = user[3]
            session['is_admin'] = user[6]
            if user[6]:
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Login failed.")
    return render_template('login.html')

# ----------------------------------------------------------------
# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password, full_name, company_name, business_id, is_admin) VALUES (%s, %s, %s, %s, %s, %s)",
                    (request.form['username'], request.form['password'], request.form['full_name'], request.form['company_name'], request.form['business_id'], False))
        conn.commit()
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

# ----------------------------------------------------------------
# User Dashboard – Agent Selection & Overview
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session or session.get('is_admin'):
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_
