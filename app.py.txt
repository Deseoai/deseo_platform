from flask import Flask, render_template, request, redirect, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'

def init_db():
    if not os.path.exists("database.db"):
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute('''CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
        c.execute('''CREATE TABLE agents (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, type TEXT)''')
        conn.commit()
        conn.close()

@app.route('/')
def home():
    return redirect('/login')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        username = request.form['username']
        password = request.form['password']
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['user_id'] = user[0]
            return redirect('/dashboard')
        else:
            return "Falsche Login-Daten"
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        username = request.form['username']
        password = request.form['password']
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        conn.close()
        return redirect('/login')
    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    if request.method == 'POST':
        name = request.form['name']
        agent_type = request.form['type']
        c.execute("INSERT INTO agents (user_id, name, type) VALUES (?, ?, ?)", (session['user_id'], name, agent_type))
        conn.commit()

    c.execute("SELECT name, type FROM agents WHERE user_id=?", (session['user_id'],))
    agents = c.fetchall()
    conn.close()
    return render_template('dashboard.html', agents=agents)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0')
