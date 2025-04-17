# app.py – vollständige, korrigierte Version
from flask import (
    Flask, render_template, request, redirect,
    session, url_for, flash
)
import os
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer

from config import config
from utils.mailer import mail, send_password_reset_email

app = Flask(__name__)
app.config.from_object(config)
# Stelle sicher, dass PASSWORD_RESET_TOKEN_MAX_AGE geladen wird
app.config['PASSWORD_RESET_TOKEN_MAX_AGE'] = config.PASSWORD_RESET_TOKEN_MAX_AGE
mail.init_app(app)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ────────────────────────────────────────────────────────────────────
# Datenbank-Hilfsfunktionen
# ────────────────────────────────────────────────────────────────────
def get_db():
    """Öffnet eine neue Datenbankverbindung."""
    try:
        return psycopg2.connect(app.config['DATABASE_URL'])
    except psycopg2.OperationalError as e:
        print(f"DB-Verbindungsfehler: {e}")
        return None

def init_db():
    """Erstellt Tabellen & Default-Admin, falls noch nicht vorhanden."""
    conn = get_db()
    if not conn:
        print("Datenbankverbindung fehlgeschlagen. Initialisierung abgebrochen.")
        return

    try:
        with conn:
            with conn.cursor() as cur:
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
                );
                """)

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
                );
                """)

                # Default-Admin
                cur.execute("SELECT 1 FROM users WHERE is_admin LIMIT 1;")
                if not cur.fetchone():
                    print("→ Erstelle Default-Admin (user: admin / pw: changeme)")
                    hashed = generate_password_hash("changeme")
                    cur.execute("""
                        INSERT INTO users 
                            (username, email, password_hash, full_name, is_admin)
                        VALUES 
                            ('admin', 'admin@example.com', %s, 'Default Admin', TRUE);
                    """, (hashed,))
    except Exception as e:
        print(f"Fehler bei der Datenbankinitialisierung: {e}")
    finally:
        conn.close()

# ────────────────────────────────────────────────────────────────────
# Routen
# ────────────────────────────────────────────────────────────────────
@app.route('/')
def home():
    return render_template('welcome.html')

# ---- Registrierung ----
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username     = request.form.get('username')
        email        = request.form.get('email')
        password     = request.form.get('password')
        full_name    = request.form.get('full_name')
        company_name = request.form.get('company_name')
        business_id  = request.form.get('business_id')

        if not all([username, email, password]):
            flash("Username, E-Mail und Passwort sind Pflichtfelder.", "warning")
            return render_template('register.html')

        hashed_pw = generate_password_hash(password)
        conn = get_db()
        if not conn:
            flash("Datenbank-Verbindung fehlgeschlagen.", "danger")
            return render_template('register.html')

        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT 1 FROM users WHERE username=%s OR email=%s",
                        (username, email)
                    )
                    if cur.fetchone():
                        flash("Username oder E-Mail existiert bereits.", "danger")
                        return render_template('register.html')

                    cur.execute("""
                        INSERT INTO users 
                            (username, email, password_hash, full_name, company_name, business_id)
                        VALUES 
                            (%s, %s, %s, %s, %s, %s);
                    """, (username, email, hashed_pw, full_name, company_name, business_id))
            flash("Registrierung erfolgreich – bitte einloggen.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash("Registrierung fehlgeschlagen (DB-Fehler).", "danger")
            print(e)
        finally:
            conn.close()
    return render_template('register.html')

# ---- Login ----
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash("Username und Passwort erforderlich.", "warning")
            return render_template('login.html')

        conn = get_db()
        if not conn:
            flash("Datenbank-Fehler.", "danger")
            return render_template('login.html')

        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, username, email, password_hash, full_name, is_admin
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
        except Exception as e:
            flash("Login fehlgeschlagen (DB-Fehler).", "danger")
            print(e)
        finally:
            conn.close()
    return render_template('login.html')

# ---- Admin-Login ----
@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db()
        if not conn:
            flash("Datenbank-Fehler.", "danger")
            return render_template('admin_login.html')

        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, username, email, password_hash, full_name, is_admin
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
                flash("Admin-Login erfolgreich!", "success")
                return redirect(url_for('admin'))

            flash("Ungültige Admin-Daten.", "danger")
        except Exception as e:
            flash("Admin-Login fehlgeschlagen (DB-Fehler).", "danger")
            print(e)
        finally:
            conn.close()
    return render_template('admin_login.html')

# ---- Logout ----
@app.route('/logout')
def logout():
    session.clear()
    flash("Abgemeldet.", "info")
    return redirect(url_for('login'))

# ---- User-Dashboard ----
@app.route('/dashboard', methods=['GET','POST'])
def dashboard():
    if 'user_id' not in session or session.get('is_admin'):
        flash("Bitte als User einloggen.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db()
    if not conn:
        flash("Datenbank-Fehler.", "danger")
        return render_template('dashboard.html')

    if request.method == 'POST':
        try:
            with conn:
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
                    # Email-Agent
                    mail_agent = request.form.get('email_agent')
                    if mail_agent:
                        cur.execute("""
                            INSERT INTO selected_agents
                            (user_id,category,name,status)
                            VALUES (%s,'email',%s,'pending')
                        """, (user_id, mail_agent))
            flash("Auswahl gespeichert – wartet auf Admin-Freigabe.", "success")
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash("Speichern fehlgeschlagen.", "danger")
            print(e)
        finally:
            conn.close()

    # GET → aktuelle Auswahl laden
    conn2 = get_db()
    selected = []
    if conn2:
        with conn2.cursor() as cur:
            cur.execute("""
                SELECT name,category,package,status
                FROM selected_agents
                WHERE user_id=%s
                ORDER BY selected_on DESC
            """, (user_id,))
            selected = cur.fetchall()
        conn2.close()

    return render_template(
        'dashboard.html',
        greeting_name=session.get('full_name', session.get('username')),
        selected_agents=selected
    )

# ---- Admin-Dashboard ----
@app.route('/admin')
def admin():
    if not session.get('admin_logged_in'):
        flash("Nur für Admins.", "warning")
        return redirect(url_for('admin_login'))

    conn = get_db()
    agents = []
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
        conn.close()

    return render_template('admin_dashboard.html', agents=agents)

# ---- Admin: View Users ----
@app.route('/admin/users')
def admin_users():
    if not session.get('admin_logged_in'):
        flash("Nur für Admins.", "warning")
        return redirect(url_for('admin_login'))

    conn = get_db()
    users = []
    if conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, username, email, full_name,
                       company_name, business_id, is_admin, registered_on
                FROM users ORDER BY id
            """)
            users = cur.fetchall()
        conn.close()

    return render_template('admin_users.html', users=users)

# ---- Admin: Activate Agent ----
@app.route('/admin/activate/<int:agent_id>', methods=['POST'])
def activate_agent(agent_id):
    if not session.get('admin_logged_in'):
        flash("Nur für Admins.", "warning")
        return redirect(url_for('admin_login'))

    conn = get_db()
    if conn:
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE selected_agents SET status='active' WHERE id=%s",
                        (agent_id,)
                    )
            flash(f"Agent {agent_id} aktiviert.", "success")
        except Exception as e:
            flash("Aktivierung fehlgeschlagen.", "danger")
            print(e)
        finally:
            conn.close()
    else:
        flash("DB-Fehler.", "danger")
    return redirect(url_for('admin'))

# ---- Passwort ändern (User) ----
@app.route('/change-password', methods=['GET','POST'])
def change_password():
    if 'user_id' not in session:
        flash("Bitte zuerst einloggen.", "warning")
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

        conn = get_db()
        if conn:
            with conn.cursor() as cur:
                cur.execute("SELECT password_hash FROM users WHERE id=%s", (session['user_id'],))
                db_hash = cur.fetchone()[0]
                if not check_password_hash(db_hash, current):
                    flash("Aktuelles Passwort falsch.", "danger")
                    conn.close()
                    return render_template('change_password.html')

                cur.execute(
                    "UPDATE users SET password_hash=%s WHERE id=%s",
                    (generate_password_hash(new), session['user_id'])
                )
                conn.commit()
            conn.close()

        flash("Passwort erfolgreich geändert.", "success")
        target = 'admin' if session.get('is_admin') else 'dashboard'
        return redirect(url_for(target))

    return render_template('change_password.html')

# ---- Passwort-Reset anfordern ----
@app.route('/request_password_reset', methods=['GET', 'POST'])
def request_password_reset():
    if request.method == 'POST':
        email = request.form.get('email')
        if not email:
            flash("E-Mail ist erforderlich.", "warning")
            return render_template('request_password_reset.html')

        conn = get_db()
        if not conn:
            flash("Datenbank-Fehler.", "danger")
            return render_template('request_password_reset.html')

        try:
            with conn.cursor() as cur:
                cur.execute("SELECT id, username, email, full_name FROM users WHERE email=%s", (email,))
                user = cur.fetchone()
            if user:
                # Benutzerobjekt erstellen
                user_dict = {'id': user[0], 'username': user[1], 'email': user[2], 'full_name': user[3]}
                # Token für Passwort-Reset generieren
                token = serializer.dumps(email, salt='password-reset-salt')
                # E-Mail senden
                send_password_reset_email(user_dict, token)
                flash("Ein Link zum Zurücksetzen des Passworts wurde an Ihre E-Mail gesendet.", "success")
            else:
                flash("E-Mail-Adresse nicht gefunden.", "danger")
        except Exception as e:
            flash("Fehler beim Senden des Reset-Links.", "danger")
            print(f"Fehler beim Passwort-Reset: {e}")
        finally:
            conn.close()
        return redirect(url_for('login'))
    return render_template('request_password_reset.html')

# ---- Passwort zurücksetzen ----
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        # Token verifizieren
        email = serializer.loads(token, salt='password-reset-salt', max_age=app.config['PASSWORD_RESET_TOKEN_MAX_AGE'])
    except Exception as e:
        flash("Der Link zum Zurücksetzen des Passworts ist ungültig oder abgelaufen.", "danger")
        print(f"Token-Fehler: {e}")
        return redirect(url_for('request_password_reset'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not all([password, confirm_password]):
            flash("Alle Felder ausfüllen.", "warning")
            return render_template('reset_password.html')

        if password != confirm_password:
            flash("Passwörter stimmen nicht überein.", "danger")
            return render_template('reset_password.html')

        conn = get_db()
        if not conn:
            flash("Datenbank-Fehler.", "danger")
            return render_template('reset_password.html')

        try:
            with conn:
                with conn.cursor() as cur:
                    hashed = generate_password_hash(password)
                    cur.execute("UPDATE users SET password_hash=%s WHERE email=%s", (hashed, email))
            flash("Passwort erfolgreich zurückgesetzt. Bitte einloggen.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash("Fehler beim Zurücksetzen des Passworts.", "danger")
            print(f"Fehler beim Passwort-Reset: {e}")
        finally:
            conn.close()
    return render_template('reset_password.html')

# ────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    with app.app_context():
        init_db()
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=True)  # Debug-Modus aktiviert
