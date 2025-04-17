# app.py – vollständige, korrigierte Version

from flask import (
    Flask, render_template, request, redirect,
    session, url_for, flash
)
import psycopg2, os
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer

from config import config
from utils.mailer import mail, send_password_reset_email

app = Flask(__name__)
app.config.from_object(config)
mail.init_app(app)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# ──────────────────────────  DB‑Hilfen  ──────────────────────────
def get_db():
    try:
        return psycopg2.connect(app.config['DATABASE_URL'])
    except psycopg2.OperationalError as e:
        print(f"DB‑Verbindungsfehler: {e}")
        return None


def init_db():
    """Legt Tabellen an und erzeugt Default‑Admin, falls nötig."""
    conn = get_db()
    if not conn:
        return

    cur = conn.cursor()
    try:
        # users
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id            SERIAL PRIMARY KEY,
            username      VARCHAR(100) UNIQUE NOT NULL,
            email         VARCHAR(120) UNIQUE NOT NULL,
            password_hash TEXT        NOT NULL,
            full_name     VARCHAR(100),
            company_name  VARCHAR(100),
            business_id   VARCHAR(50),
            is_admin      BOOLEAN     DEFAULT FALSE,
            registered_on TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );""")

        # selected_agents
        cur.execute("""
        CREATE TABLE IF NOT EXISTS selected_agents(
            id          SERIAL PRIMARY KEY,
            user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
            name        VARCHAR(100) NOT NULL,
            category    VARCHAR(50)  NOT NULL,
            package     VARCHAR(50),
            status      VARCHAR(20)  DEFAULT 'pending',
            selected_on TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );""")

        # Default‑Admin anlegen
        cur.execute("SELECT 1 FROM users WHERE is_admin LIMIT 1;")
        if not cur.fetchone():
            print("→ Erstelle Default‑Admin (user: admin / pw: changeme)")
            hashed = generate_password_hash("changeme")
            cur.execute("""
                INSERT INTO users (username, email, password_hash,
                                   full_name, is_admin)
                VALUES ('admin', 'admin@example.com', %s,
                        'Default Admin', TRUE);
            """, (hashed,))
        conn.commit()
    finally:
        cur.close()
        conn.close()


# ──────────────────────────  Routen ──────────────────────────────

@app.route('/')
def home():
    return render_template('welcome.html')


# ---------- Registrierung ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        u = request.form
        if not all([u.get('username'), u.get('email'), u.get('password')]):
            flash("Username, E‑Mail und Passwort sind Pflichtfelder.", "warning")
            return render_template('register.html')

        hashed_pw = generate_password_hash(u['password'])
        conn = get_db()
        if not conn:
            flash("Datenbank‑Verbindung fehlgeschlagen.", "danger")
            return render_template('register.html')

        cur = conn.cursor()
        try:
            cur.execute(
                "SELECT 1 FROM users WHERE username=%s OR email=%s",
                (u['username'], u['email'])
            )
            if cur.fetchone():
                flash("Username oder E‑Mail existiert bereits.", "danger")
                return render_template('register.html')

            cur.execute("""
                INSERT INTO users (username, email, password_hash,
                                   full_name, company_name, business_id)
                VALUES (%s,%s,%s,%s,%s,%s);
            """, (
                u['username'], u['email'], hashed_pw,
                u.get('full_name'), u.get('company_name'),
                u.get('business_id')
            ))
            conn.commit()
            flash("Registrierung erfolgreich – bitte einloggen.", "success")
            return redirect(url_for('login'))

        except psycopg2.Error as e:
            conn.rollback()
            flash("Registrierung fehlgeschlagen (DB‑Fehler).", "danger")
            print(e)
        finally:
            cur.close()
            conn.close()

    return render_template('register.html')


# ---------- Login ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash("Username und Passwort erforderlich.", "warning")
            return render_template('login.html')

        conn = get_db()
        if not conn:
            flash("Datenbank‑Fehler.", "danger")
            return render_template('login.html')

        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT id, username, email, password_hash,
                       full_name, is_admin
                  FROM users
                 WHERE username=%s
            """, (username,))
            user_row = cur.fetchone()

            if user_row and check_password_hash(user_row[3], password):
                session.update({
                    "user_id":   user_row[0],
                    "username":  user_row[1],
                    "full_name": user_row[4],
                    "is_admin":  user_row[5]
                })
                flash("Login erfolgreich!", "success")
                return redirect(
                    url_for('admin' if user_row[5] else 'dashboard')
                )

            flash("Ungültige Zugangsdaten.", "danger")

        except psycopg2.Error as e:
            flash("Login fehlgeschlagen (DB‑Fehler).", "danger")
            print(e)
        finally:
            cur.close()
            conn.close()

    return render_template('login.html')


# ---------- Admin‑Login ----------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db()
        if not conn:
            flash("DB‑Fehler.", "danger")
            return render_template('admin_login.html')

        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT id, username, email, password_hash,
                       full_name, is_admin
                  FROM users
                 WHERE username=%s AND is_admin=TRUE
            """, (username,))
            admin_row = cur.fetchone()

            if admin_row and check_password_hash(admin_row[3], password):
                session.update({
                    "user_id":        admin_row[0],
                    "username":       admin_row[1],
                    "full_name":      admin_row[4],
                    "is_admin":       True,
                    "admin_logged_in": True
                })
                flash("Admin‑Login erfolgreich!", "success")
                return redirect(url_for('admin'))

            flash("Ungültige Admin‑Daten.", "danger")

        except psycopg2.Error as e:
            flash("Admin‑Login DB‑Fehler.", "danger")
            print(e)
        finally:
            cur.close()
            conn.close()

    return render_template('admin_login.html')


# ---------- Logout ----------
@app.route('/logout')
def logout():
    session.clear()
    flash("Abgemeldet.", "info")
    return redirect(url_for('login'))


# ---------- User‑Dashboard ----------
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    # Nur für eingeloggt‑nicht‑admin
    if 'user_id' not in session or session.get('is_admin'):
        flash("Bitte als User einloggen.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']

    # POST: Agenten speichern
    if request.method == 'POST':
        conn = get_db()
        if not conn:
            flash("DB‑Fehler beim Speichern.", "danger")
            return redirect(url_for('dashboard'))

        cur = conn.cursor()
        try:
            # Inbound
            for val in request.form.getlist('inbound_agents'):
                name, package = val.split('|')
                cur.execute("""
                    INSERT INTO selected_agents
                      (user_id, category, name, package, status)
                    VALUES (%s, 'inbound', %s, %s, 'pending')
                """, (user_id, name, package))

            # Outbound
            for nm in request.form.getlist('outbound_agents'):
                cur.execute("""
                    INSERT INTO selected_agents
                      (user_id, category, name, status)
                    VALUES (%s, 'outbound', %s, 'pending')
                """, (user_id, nm))

            # Email‑Agent
            mail_agent = request.form.get('email_agent')
            if mail_agent:
                cur.execute("""
                    INSERT INTO selected_agents
                      (user_id, category, name, status)
                    VALUES (%s, 'email', %s, 'pending')
                """, (user_id, mail_agent))

            conn.commit()
            flash("Auswahl gespeichert – wartet auf Admin‑Freigabe.", "success")

        except psycopg2.Error as e:
            conn.rollback()
            flash("Speichern fehlgeschlagen.", "danger")
            print(e)
        finally:
            cur.close()
            conn.close()

        return redirect(url_for('dashboard'))

    # GET: Bisherige Agenten anzeigen
    conn = get_db()
    selected = []
    if conn:
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT name, category, package, status
                  FROM selected_agents
                 WHERE user_id=%s
              ORDER BY selected_on DESC
            """, (user_id,))
            selected = cur.fetchall()
        except psycopg2.Error as e:
            flash("Laden fehlgeschlagen.", "warning")
            print(e)
        finally:
            cur.close()
            conn.close()

    return render_template(
        'dashboard.html',
        greeting_name=session.get('full_name', session['username']),
        selected_agents=selected
    )


# ---------- Admin‑Dashboard ----------
@app.route('/admin')
def admin():
    if not session.get('admin_logged_in'):
        flash("Nur für Admins.", "warning")
        return redirect(url_for('admin_login'))

    conn = get_db()
    agents = []
    if conn:
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT a.id, u.username, u.full_name,
                       a.name, a.category, a.package, a.status
                  FROM selected_agents a
                  JOIN users u ON a.user_id=u.id
              ORDER BY a.selected_on DESC
            """)
            agents = cur.fetchall()
        except psycopg2.Error as e:
            flash("Fehler beim Laden.", "danger")
            print(e)
        finally:
            cur.close()
            conn.close()

    return render_template('admin_dashboard.html', agents=agents)


# ---------- Admin: User‑Liste ----------
@app.route('/admin/users')
def admin_users():
    if not session.get('admin_logged_in'):
        flash("Nur für Admins.", "warning")
        return redirect(url_for('admin_login'))

    conn = get_db()
    users = []
    if conn:
        cur = conn.cursor()
        try:
            cur.execute("""
                SELECT id, username, email, full_name,
                       company_name, business_id,
                       is_admin, registered_on
                  FROM users
              ORDER BY id
            """)
            users = cur.fetchall()
        except psycopg2.Error as e:
            flash("Fehler beim Laden der User.", "danger")
            print(e)
        finally:
            cur.close()
            conn.close()

    return render_template('admin_users.html', users=users)


# ---------- Admin aktiviert Agenten ----------
@app.route('/admin/activate/<int:agent_id>', methods=['POST'])
def activate_agent(agent_id):
    if not session.get('admin_logged_in'):
        flash("Nur für Admins.", "warning")
        return redirect(url_for('admin_login'))

    conn = get_db()
    if not conn:
        flash("DB‑Fehler.", "danger")
        return redirect(url_for('admin'))

    cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE selected_agents
               SET status='active'
             WHERE id=%s
        """, (agent_id,))
        conn.commit()
        flash(f"Agent {agent_id} aktiviert.", "success")
    except psycopg2.Error as e:
        conn.rollback()
        flash("Aktivierung fehlgeschlagen.", "danger")
        print(e)
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('admin'))


# ─────────────────────  App‑Start  ──────────────────────
if __name__ == "__main__":
    with app.app_context():
        init_db()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
