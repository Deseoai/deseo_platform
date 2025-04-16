from flask import Flask, render_template, request, redirect, session, url_for
import psycopg2
import os
from config import DATABASE_URL

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Datenbank initialisieren
def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()

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

def get_db():
    return psycopg2.connect(DATABASE_URL)

# Welcome page
@app.route('/')
def home():
    return render_template('welcome.html')

# Login
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

# Registrierung
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

# Dashboard User
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session or session.get('is_admin'):
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db()
    cur = conn.cursor()

    if request.method == 'POST':
        inbound = request.form.getlist('inbound_agents')
        for val in inbound:
            name, package = val.split('|')
            cur.execute("INSERT INTO selected_agents (user_id, category, name, package, status) VALUES (%s, %s, %s, %s, %s)",
                        (user_id, 'inbound', name, package, 'pending'))

        outbound = request.form.getlist('outbound_agents')
        for name in outbound:
            cur.execute("INSERT INTO selected_agents (user_id, category, name, package, status) VALUES (%s, %s, %s, %s, %s)",
                        (user_id, 'outbound', name, None, 'pending'))

        email = request.form.get('email_agent')
        if email:
            cur.execute("INSERT INTO selected_agents (user_id, category, name, package, status) VALUES (%s, %s, %s, %s, %s)",
                        (user_id, 'email', email, None, 'pending'))

        conn.commit()

    cur.execute("SELECT name, category, package, status FROM selected_agents WHERE user_id=%s", (user_id,))
    selected_agents = cur.fetchall()
    conn.close()
    return render_template('dashboard.html', greeting_name=session['full_name'], selected_agents=selected_agents)

# Admin Login
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=%s AND password=%s AND is_admin=TRUE",
                    (request.form['username'], request.form['password']))
        admin = cur.fetchone()
        conn.close()
        if admin:
            session['admin_logged_in'] = True
            return redirect(url_for('admin'))
        else:
            return render_template('login.html', error="Admin login failed.")
    return render_template('login.html')

# Admin Dashboard
@app.route('/admin')
def admin():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT a.id, u.full_name, a.name, a.category, a.package, a.status FROM selected_agents a JOIN users u ON a.user_id = u.id")
    agents = cur.fetchall()
    conn.close()
    return render_template('admin_dashboard.html', agents=agents)

# Admin Users Übersicht (neu!)
@app.route('/admin/users')
def admin_users():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, full_name, company_name, business_id FROM users ORDER BY id ASC")
    users = cur.fetchall()
    conn.close()
    return render_template('admin_users.html', users=users)

# Activate Agents
@app.route('/admin/activate/<int:agent_id>', methods=['POST'])
def activate_agent(agent_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE selected_agents SET status='active' WHERE id=%s", (agent_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('admin'))

# Logout
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Port fix und Start
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
