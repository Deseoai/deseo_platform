# app.py – stabile Vollversion (ohne Change-Password)
from flask import Flask, render_template, request, redirect, session, url_for, flash
import psycopg2, os
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer

from config import config
from utils.mailer import mail, send_password_reset_email

app = Flask(__name__)
app.config.from_object(config)
mail.init_app(app)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


def get_db():
    try:
        return psycopg2.connect(app.config['DATABASE_URL'])
    except psycopg2.OperationalError as e:
        print(f"DB‑Verbindungsfehler: {e}")
        return None


def init_db():
    conn = get_db()
    if not conn:
        return
    with conn, conn.cursor() as cur:
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            email VARCHAR(120) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name VARCHAR(100),
            company_name VARCHAR(100),
            business_id VARCHAR(50),
            is_admin BOOLEAN DEFAULT FALSE,
            registered_on TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS selected_agents(
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            name VARCHAR(100) NOT NULL,
            category VARCHAR(50) NOT NULL,
            package VARCHAR(50),
            status VARCHAR(20) DEFAULT 'pending',
            selected_on TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
        """)
        cur.execute("SELECT 1 FROM users WHERE is_admin LIMIT 1;")
        if not cur.fetchone():
            print("→ Erstelle Default‑Admin (user: admin / pw: changeme)")
            cur.execute("""
                INSERT INTO users (username, email, password_hash, full_name, is_admin)
                VALUES ('admin','admin@example.com',%s,'Default Admin',TRUE);
            """, (generate_password_hash("changeme"),))


@app.route('/')
def home():
    return render_template('welcome.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form
        if not u['username'] or not u['email'] or not u['password']:
            flash("Username, E‑Mail und Passwort sind Pflichtfelder.", "warning")
            return render_template('register.html')
        conn = get_db()
        if not conn:
            flash("Datenbank‑Fehler.", "danger")
            return render_template('register.html')
        try:
            with conn, conn.cursor() as cur:
                cur.execute("SELECT 1 FROM users WHERE username=%s OR email=%s",
                            (u['username'], u['email']))
                if cur.fetchone():
                    flash("Username oder E‑Mail existiert bereits.", "danger")
                    return render_template('register.html')
                cur.execute("""
                    INSERT INTO users
                       (username,email,password_hash,full_name,company_name,business_id)
                    VALUES (%s,%s,%s,%s,%s,%s);
                """, (
                    u['username'], u['email'],
                    generate_password_hash(u['password']),
                    u.get('full_name'), u.get('company_name'), u.get('business_id')
                ))
            flash("Registrierung erfolgreich – bitte einloggen.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash("Registrierung fehlgeschlagen.", "danger")
            print(e)
        finally:
            conn.close()
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u, p = request.form.get('username'), request.form.get('password')
        if not u or not p:
            flash("Username und Passwort erforderlich.", "warning")
            return render_template('login.html')
        conn = get_db()
        if not conn:
            flash("Datenbank‑Fehler.", "danger")
            return render_template('login.html')
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id,username,password_hash,full_name,is_admin
                    FROM users WHERE username=%s
                """, (u,))
                row = cur.fetchone()
            if row and check_password_hash(row[2], p):
                session.update({
                    'user_id': row[0],
                    'username': row[1],
                    'full_name': row[3],
                    'is_admin': row[4],
                    'admin_logged_in': row[4]
                })
                flash("Login erfolgreich!", "success")
                return redirect(url_for('admin' if row[4] else 'dashboard'))
            flash("Ungültige Zugangsdaten.", "danger")
        except Exception as e:
            flash("Login fehlgeschlagen.", "danger")
            print(e)
        finally:
            conn.close()
    return render_template('login.html')


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        u, p = request.form.get('username'), request.form.get('password')
        conn = get_db()
        if not conn:
            flash("DB‑Fehler.", "danger")
            return render_template('admin_login.html')
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id,username,password_hash,full_name
                    FROM users WHERE username=%s AND is_admin=TRUE
                """, (u,))
                adm = cur.fetchone()
            if adm and check_password_hash(adm[2], p):
                session.update({
                    'user_id': adm[0],
                    'username': adm[1],
                    'full_name': adm[3],
                    'is_admin': True,
                    'admin_logged_in': True
                })
                flash("Admin‑Login erfolgreich!", "success")
                return redirect(url_for('admin'))
            flash("Ungültige Admin‑Daten.", "danger")
        except Exception as e:
            flash("Admin‑Login fehlgeschlagen.", "danger")
            print(e)
        finally:
            conn.close()
    return render_template('admin_login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("Abgemeldet.", "info")
    return redirect(url_for('login'))


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session or session.get('is_admin'):
        flash("Bitte als User einloggen.", "warning")
        return redirect(url_for('login'))
    conn = get_db()
    if not conn:
        flash("DB‑Fehler.", "danger")
        return render_template('dashboard.html')
    if request.method == 'POST':
        try:
            with conn.cursor() as cur:
                for val in request.form.getlist('inbound_agents'):
                    nm, pkg = val.split('|')
                    cur.execute("""
                        INSERT INTO selected_agents
                        (user_id,category,name,package,status)
                        VALUES (%s,'inbound',%s,%s,'pending')
                    """, (session['user_id'], nm, pkg))
                for nm in request.form.getlist('outbound_agents'):
                    cur.execute("""
                        INSERT INTO selected_agents
                        (user_id,category,name,status)
                        VALUES (%s,'outbound',%s,'pending')
                    """, (session['user_id'], nm))
                mail_ag = request.form.get('email_agent')
                if mail_ag:
                    cur.execute("""
                        INSERT INTO selected_agents
                        (user_id,category,name,status)
                        VALUES (%s,'email',%s,'pending')
                    """, (session['user_id'], mail_ag))
                conn.commit()
                flash("Auswahl gespeichert.", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            conn.rollback()
            flash("Speichern fehlgeschlagen.", "danger")
            print(e)
        finally:
            conn.close()
    # GET
    agents = []
    with get_db() as gc:
        if gc:
            with gc.cursor() as cur:
                cur.execute("""
                    SELECT name,category,package,status
                    FROM selected_agents
                    WHERE user_id=%s
                    ORDER BY selected_on DESC
                """, (session['user_id'],))
                agents = cur.fetchall()
    return render_template('dashboard.html',
                           greeting_name=session.get('full_name'),
                           selected_agents=agents)


@app.route('/admin')
def admin():
    if not session.get('admin_logged_in'):
        flash("Nur für Admins.", "warning")
        return redirect(url_for('admin_login'))
    data = []
    with get_db() as conn:
        if conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT a.id,u.username,u.full_name,a.name,a.category,a.package,a.status
                    FROM selected_agents a
                    JOIN users u ON a.user_id=u.id
                    ORDER BY a.selected_on DESC
                """)
                data = cur.fetchall()
    return render_template('admin_dashboard.html', agents=data)


@app.route('/admin/users')
def admin_users():
    if not session.get('admin_logged_in'):
        flash("Nur für Admins.", "warning")
        return redirect(url_for('admin_login'))
    users = []
    with get_db() as conn:
        if conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id,username,email,full_name,company_name,business_id,is_admin,registered_on
                    FROM users ORDER BY id
                """)
                users = cur.fetchall()
    return render_template('admin_users.html', users=users)


@app.route('/admin/activate/<int:agent_id>', methods=['POST'])
def activate_agent(agent_id):
    if not session.get('admin_logged_in'):
        flash("Nur für Admins.", "warning")
        return redirect(url_for('admin_login'))
    conn = get_db()
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("UPDATE selected_agents SET status='active' WHERE id=%s", (agent_id,))
            conn.commit()
            flash(f"Agent {agent_id} aktiviert.", "success")
        except Exception as e:
            conn.rollback()
            flash("Aktivierung fehlgeschlagen.", "danger")
            print(e)
        finally:
            conn.close()
    return redirect(url_for('admin'))


@app.route('/request_password_reset', methods=['GET','POST'])
def request_password_reset():
    return render_template('request_password_reset.html')


@app.route('/reset-password/<token>', methods=['GET','POST'])
def reset_password(token):
    return render_template('reset_password.html')


if __name__ == "__main__":
    with app.app_context():
        init_db()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
