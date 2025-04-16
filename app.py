from flask import Flask, render_template, request, redirect, session, url_for
import psycopg2
from config import DATABASE_URL

app = Flask(__name__)
app.secret_key = "supersecretkey"

def get_db():
    return psycopg2.connect(DATABASE_URL)

@app.route('/')
def home():
    return redirect(url_for('login'))

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
            return render_template('login.html', error="Login fehlgeschlagen.")
    return render_template('login.html')

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

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session or session.get('is_admin'):
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db()
    cur = conn.cursor()
    
    if request.method == 'POST':
        # Inbound
        inbound = request.form.getlist('inbound_agents')
        for val in inbound:
            name, package = val.split('|')
            cur.execute("INSERT INTO selected_agents (user_id, category, name, package, status) VALUES (%s, %s, %s, %s, %s)",
                        (user_id, 'inbound', name, package, 'pending'))

        # Outbound
        outbound = request.form.getlist('outbound_agents')
        for name in outbound:
            cur.execute("INSERT INTO selected_agents (user_id, category, name, package, status) VALUES (%s, %s, %s, %s, %s)",
                        (user_id, 'outbound', name, None, 'pending'))

        # E-Mail Agent
        email = request.form.get('email_agent')
        if email:
            cur.execute("INSERT INTO selected_agents (user_id, category, name, package, status) VALUES (%s, %s, %s, %s, %s)",
                        (user_id, 'email', email, None, 'pending'))

        conn.commit()

    cur.execute("SELECT name, category, package, status FROM selected_agents WHERE user_id=%s", (user_id,))
    selected_agents = cur.fetchall()
    conn.close()
    return render_template('dashboard.html', greeting_name=session['full_name'], selected_agents=selected_agents)

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
            return render_template('login.html', error="Admin Login fehlgeschlagen.")
    return render_template('login.html')

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

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ✅ Fix für Render – bindet an 0.0.0.0 auf Port 10000
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
