from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"
DB_NAME = "database.db"

def init_db():
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT,
                password TEXT,
                full_name TEXT,
                company_name TEXT,
                business_id TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE agents (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                name TEXT,
                type TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE selected_agents (
                id INTEGER PRIMARY KEY,
                user_id INTEGER,
                category TEXT,
                name TEXT,
                package TEXT
            )
        ''')
        conn.commit()
        conn.close()

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()

        if user:
            session['user_id'] = user[0]
            session['full_name'] = user[3]
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Falsche Login-Daten!")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']
        company_name = request.form['company_name']
        business_id = request.form['business_id']

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("""
            INSERT INTO users (username, password, full_name, company_name, business_id)
            VALUES (?, ?, ?, ?, ?)
        """, (username, password, full_name, company_name, business_id))
        conn.commit()
        conn.close()

        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    if request.method == 'POST':
        # Inbound Agenten
        inbound = request.form.getlist('inbound_agents')
        for val in inbound:
            agent_type, package = val.split('|')
            c.execute("INSERT INTO selected_agents (user_id, category, name, package) VALUES (?, ?, ?, ?)",
                      (user_id, 'inbound', agent_type, package))

        # Outbound Agenten
        outbound = request.form.getlist('outbound_agents')
        for name in outbound:
            c.execute("INSERT INTO selected_agents (user_id, category, name, package) VALUES (?, ?, ?, ?)",
                      (user_id, 'outbound', name, None))

        # E-Mail Agent
        email = request.form.get('email_agent')
        if email:
            c.execute("INSERT INTO selected_agents (user_id, category, name, package) VALUES (?, ?, ?, ?)",
                      (user_id, 'email', email, None))

        conn.commit()

    # Agenten anzeigen
    c.execute("SELECT * FROM selected_agents WHERE user_id=?", (user_id,))
    selected_agents = c.fetchall()
    conn.close()

    greeting_name = session.get('full_name', 'Kunde')
    return render_template('dashboard.html', greeting_name=greeting_name, selected_agents=selected_agents)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
