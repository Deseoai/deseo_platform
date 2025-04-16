from flask import Flask, render_template, request, redirect, session, url_for
import psycopg2
from config import DATABASE_URL

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ✅ Automatische Tabellenerstellung
def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

    # Users Tabelle
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(100) NOT NULL,
        full_name VARCHAR(200),
        company_name VARCHAR(200),
        business_id VARCHAR(100),
        is_admin BOOLEAN DEFAULT FALSE
    );
    """)

    # Selected Agents Tabelle
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
    cur.close()
    conn.close()

def get_db():
    return psycopg2.connect(DATABASE_URL)

@app.route('/')
def home():
    return render_template('welcome.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        conn = get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password, full_name, company_name, business_id) VALUES (%s, %s, %s, %s, %s)",
                    (request.form['username'], request.form['password'], request.form['full_name'], request.form['company_name'], request.form['business_id']))
        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=%s AND password=%s",
                    (request.form['username'], request.form['password']))
        user = cur.fetchone()
        cur.close()
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
            return render_template('login.html', error="Invalid credentials.")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', greeting_name=session.get('full_name'))

@app.route('/admin')
def admin():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('login'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM selected_agents")
    agents = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('admin_dashboard.html', agents=agents)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=10000)
