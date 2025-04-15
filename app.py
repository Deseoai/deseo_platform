from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"

DB_NAME = "database.db"

def init_db():
    """Erstellt eine SQLite-DB mit erweiterter Users-Tabelle."""
    if not os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        # Neue Users-Tabelle mit mehr Spalten:
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
        conn.commit()
        conn.close()

@app.route('/')
def home():
    # Fürs Branding leiten wir direkt auf /login
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login-Seite mit Bootstrap-Formular."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()

        if user:
            # User-Daten in Session
            session['user_id'] = user[0]
            session['full_name'] = user[3]  # index 3 = full_name
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Falsche Login-Daten!")

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Erweiterte Registrierung: Name, Firma, Business-ID."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        full_name = request.form['full_name']
        company_name = request.form['company_name']
        business_id = request.form['business_id']

        # Daten speichern
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
    """Dashboard mit Agenten-Liste und Formular zum Anlegen neuer Agenten."""
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    if request.method == 'POST':
        # Neuen Agenten anlegen
        name = request.form['name']
        agent_type = request.form['type']
        c.execute("INSERT INTO agents (user_id, name, type) VALUES (?, ?, ?)", (user_id, name, agent_type))
        conn.commit()

    # Agenten abfragen, die dem eingelog. User gehören
    c.execute("SELECT name, type FROM agents WHERE user_id=?", (user_id,))
    agents = c.fetchall()
    conn.close()

    # Zeigen, wie der User heißt:
    greeting_name = session.get('full_name', 'Lieber Nutzer')

    return render_template('dashboard.html', agents=agents, greeting_name=greeting_name)

@app.route('/logout')
def logout():
    """Session leeren = ausloggen."""
    session.clear()
    return redirect(url_for('login'))

if __name__ == "__main__":
    init_db()
    # Server auf allen IPs (damit Render zugreifen kann)
    app.run(host="0.0.0.0", port=5000, debug=True)
