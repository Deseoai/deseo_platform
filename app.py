# app.py – korrigierte Vollversion
from flask import (
    Flask, render_template, request, redirect,
    session, url_for, flash
)
import psycopg2, os
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer

from config import config
from utils.mailer import mail                      # Mail‑Modul unverändert

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
    """Legt Tabellen an und erzeugt einen Default‑Admin, falls nötig."""
    conn = get_db()
    if not conn:
        return

    with conn, conn.cursor() as cur:
        # ---------- users ----------
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id            SERIAL PRIMARY KEY,
            username      VARCHAR(100) UNIQUE NOT NULL,
            email         VARCHAR(120) UNIQUE NOT NULL,
            password_hash TEXT        NOT NULL,          -- <‑‑ hier geändert
            full_name     VARCHAR(100),
            company_name  VARCHAR(100),
            business_id   VARCHAR(50),
            is_admin      BOOLEAN     DEFAULT FALSE,
            registered_on TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # ---------- selected_agents ----------
        cur.execute("""
        CREATE TABLE IF NOT EXISTS selected_agents(
            id          SERIAL PRIMARY KEY,
            user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
            name        VARCHAR(100) NOT NULL,
            category    VARCHAR(50)  NOT NULL,
            package     VARCHAR(50),
            status      VARCHAR(20)  DEFAULT 'pending',
            selected_on TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );
        """)

        # ---------- Default‑Admin ----------
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

# ──────────────────────────  Routen (alles wie gehabt) ───────────
@app.route('/')
def home():
    return render_template('welcome.html')

# ---------- Registrierung ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username      = request.form.get('username')
        email         = request.form.get('email')
        password      = request.form.get('password')
        full_name     = request.form.get('full_name')
        company_name  = request.form.get('company_name')
        business_id   = request.form.get('business_id')

        if not all([username, email, password]):
            flash("Username, E‑Mail und Passwort sind Pflichtfelder.", "warning")
            return render_template('register.html')

        hashed_pw = generate_password_hash(password)
        conn = get_db()
        if not conn:
            flash("Datenbank‑Verbindung fehlgeschlagen.", "danger")
            return render_template('register.html')

        try:
            with conn, conn.cursor() as cur:
                cur.execute("SELECT 1 FROM users WHERE username=%s OR email=%s",
                            (username, email))
                if cur.fetchone():
                    flash("Username oder E‑Mail existiert bereits.", "danger")
                    return render_template('register.html')

                cur.execute("""
                    INSERT INTO users (username, email, password_hash,
                                       full_name, company_name, business_id)
                    VALUES (%s,%s,%s,%s,%s,%s);
                """, (username, email, hashed_pw,
                      full_name, company_name, business_id))
                flash("Registrierung erfolgreich – bitte einloggen.", "success")
                return redirect(url_for('login'))
        except psycopg2.Error as e:
            flash("Registrierung fehlgeschlagen (DB‑Fehler).", "danger")
            print(e)
        finally:
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

        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, username, email, password_hash,
                           full_name, is_admin
                    FROM users WHERE username=%s
                """, (username,))
                u = cur.fetchone()

            if u and check_password_hash(u[3], password):
                session.update({
                    "user_id":   u[0],
                    "username":  u[1],
                    "full_name": u[4],
                    "is_admin":  u[5]
                })
                flash("Login erfolgreich!", "success")
                return redirect(url_for('admin' if u[5] else 'dashboard'))
            flash("Ungültige Zugangsdaten.", "danger")
        except psycopg2.Error as e:
            flash("Login fehlgeschlagen (DB‑Fehler).", "danger")
            print(e)
        finally:
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

        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, username, email, password_hash,
                           full_name, is_admin
                    FROM users
                    WHERE username=%s AND is_admin=TRUE
                """, (username,))
                adm = cur.fetchone()

            if adm and check_password_hash(adm[3], password):
                session.update({
                    "user_id": adm[0],
                    "username": adm[1],
                    "full_name": adm[4],
                    "is_admin": True,
                    "admin_logged_in": True
                })
                flash("Admin‑Login erfolgreich!", "success")
                return redirect(url_for('admin'))
            flash("Ungültige Admin‑Daten.", "danger")
        except psycopg2.Error as e:
            flash("Admin‑Login DB‑Fehler.", "danger")
            print(e)
        finally:
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
    if 'user_id' not in session or session.get('is_admin'):
        flash("Bitte als User einloggen.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db()
    if not conn:
        flash("DB‑Fehler.", "danger")
        return render_template('dashboard.html')

    if request.method == 'POST':
        try:
            with conn.cursor() as cur:
                # Inbound
                for val in request.form.getlist('inbound_agents'):
                    name, package = val.split('|')
                    cur.execute("""
                        INSERT INTO selected_agents
                        (user_id,category,name,package,status)
                        VALUES (%s,'inbound',%s,%s,'pending')
                    """, (user_id, name, package))

                # Outbound
                for nm in request.form.getlist('outbound_agents'):
                    cur.execute("""
                        INSERT INTO selected_agents
                        (user_id,category,name,status)
                        VALUES (%s,'outbound',%s,'pending')
                    """, (user_id, nm))

                # Mail
                mail_agent = request.form.get('email_agent')
                if mail_agent:
                    cur.execute("""
                        INSERT INTO selected_agents
                        (user_id,category,name,status)
                        VALUES (%s,'email',%s,'pending')
                    """, (user_id, mail_agent))

                conn.commit()
                flash("Auswahl gespeichert – wartet auf Admin‑Freigabe.", "success")
            return redirect(url_for('dashboard'))
        except psycopg2.Error as e:
            conn.rollback()
            flash("Speichern fehlgeschlagen.", "danger")
            print(e)
        finally:
            conn.close()

    # GET → aktuelle Agenten
    selected = []
    with get_db() as gconn:
        if gconn:
            with gconn.cursor() as cur:
                cur.execute("""
                    SELECT name,category,package,status
                    FROM selected_agents
                    WHERE user_id=%s
                    ORDER BY selected_on DESC
                """, (user_id,))
                selected = cur.fetchall()

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

    agents = []
    with get_db() as conn:
        if conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT a.id, u.username, u.full_name,
                           a.name, a.category, a.package, a.status
                    FROM selected_agents a
                    JOIN users u ON a.user_id=u.id
                    ORDER BY a.selected_on DESC
                """)
                agents = cur.fetchall()

    return render_template('admin_dashboard.html', agents=agents)

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
                    SELECT id,username,email,full_name,
                           company_name,business_id,is_admin,registered_on
                    FROM users ORDER BY id
                """)
                users = cur.fetchall()

    return render_template('admin_users.html', users=users)

@app.route('/admin/activate/<int:agent_id>', methods=['POST'])
def activate_agent(agent_id):
    if not session.get('admin_logged_in'):
        flash("Nur für Admins.", "warning")
        return redirect(url_for('admin_login'))

    with get_db() as conn:
        if not conn:
            flash("DB‑Fehler.", "danger")
            return redirect(url_for('admin'))

        try:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE selected_agents
                    SET status='active' WHERE id=%s
                """, (agent_id,))
            conn.commit()
            flash(f"Agent {agent_id} aktiviert.", "success")
        except psycopg2.Error as e:
            conn.rollback()
            flash("Aktivierung fehlgeschlagen.", "danger")
            print(e)

    return redirect(url_for('admin'))

# ---------- Passwort‑Reset‑Platzhalter ----------
@app.route('/request_password_reset')
def request_password_reset():
    return render_template('request_password_reset.html')

@app.route('/reset-password/<token>')
def reset_password(token):
    return render_template('reset_password.html')

# ---------- Passwort ändern (nur eingeloggte User) ----------
@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash("Bitte erst einloggen.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        current = request.form.get('current_password')
        new     = request.form.get('new_password')
        repeat  = request.form.get('repeat_password')

        if not all([current, new, repeat]):
            flash("Alle Felder ausfüllen.", "warning")
            return render_template('change_password.html')

        if new != repeat:
            flash("Neue Passwörter stimmen nicht überein.", "danger")
            return render_template('change_password.html')

        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT password_hash FROM users WHERE id=%s",
                            (session['user_id'],))
                db_hash, = cur.fetchone()

                if not check_password_hash(db_hash, current):
                    flash("Aktuelles Passwort falsch.", "danger")
                    return render_template('change_password.html')

                cur.execute("UPDATE users SET password_hash=%s WHERE id=%s",
                            (generate_password_hash(new), session['user_id']))
                conn.commit()
                flash("Passwort erfolgreich geändert.", "success")
                return redirect(url_for('dashboard' if not session.get('is_admin') else 'admin'))

    return render_template('change_password.html')



# ─────────────────────  App‑Start  ──────────────────────
if __name__ == "__main__":
    with app.app_context():
        init_db()                                # Tabellenerstellung & Default‑Admin
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
