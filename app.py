# app.py – voll korrigierte Version
import os
from flask import (
    Flask, render_template, request, redirect,
    session, url_for, flash
)
import psycopg2
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
        # psycopg2.connect unterstützt SSL via ?sslmode=require in URL
        return psycopg2.connect(app.config['DATABASE_URL'])
    except psycopg2.OperationalError as e:
        print(f"DB‑Verbindungsfehler: {e}")
        return None


def init_db():
    conn = get_db()
    if not conn:
        return
    try:
        cur = conn.cursor()
        # users-Tabelle (passwort_hash jetzt TEXT)
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
        # selected_agents-Tabelle
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
        conn.commit()

        # Default‑Admin anlegen, falls noch keiner existiert
        cur.execute("SELECT 1 FROM users WHERE is_admin LIMIT 1;")
        if not cur.fetchone():
            print("→ Erstelle Default‑Admin (user: admin / pw: changeme)")
            default_pw = generate_password_hash("changeme")
            cur.execute("""
                INSERT INTO users
                  (username, email, password_hash, full_name, is_admin)
                VALUES
                  ('admin', 'admin@example.com', %s, 'Default Admin', TRUE)
            """, (default_pw,))
            conn.commit()
    finally:
        conn.close()


# ──────────────────────────  Routen  ────────────────────────────

@app.route('/')
def home():
    return render_template('welcome.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username     = request.form.get('username')
        email        = request.form.get('email')
        password     = request.form.get('password')
        full_name    = request.form.get('full_name')
        company_name = request.form.get('company_name')
        business_id  = request.form.get('business_id')

        if not all([username, email, password]):
            flash("Username, E‑Mail und Passwort sind Pflichtfelder.", "warning")
            return render_template('register.html')

        conn = get_db()
        if not conn:
            flash("Datenbank‑Verbindung fehlgeschlagen.", "danger")
            return render_template('register.html')

        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT 1 FROM users WHERE username=%s OR email=%s",
                (username, email)
            )
            if cur.fetchone():
                flash("Username oder E‑Mail bereits vergeben.", "danger")
                return render_template('register.html')

            hashed_pw = generate_password_hash(password)
            cur.execute("""
                INSERT INTO users
                  (username, email, password_hash, full_name, company_name, business_id)
                VALUES
                  (%s, %s, %s, %s, %s, %s);
            """, (username, email, hashed_pw, full_name, company_name, business_id))
            conn.commit()
            flash("Registrierung erfolgreich – bitte einloggen.", "success")
            return redirect(url_for('login'))
        except psycopg2.Error as e:
            print(f"Registrierungs‑DB‑Fehler: {e}")
            flash("Registrierung fehlgeschlagen.", "danger")
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not all([username, password]):
            flash("Username und Passwort erforderlich.", "warning")
            return render_template('login.html')

        conn = get_db()
        if not conn:
            flash("Datenbank‑Fehler.", "danger")
            return render_template('login.html')

        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT id, username, password_hash, full_name, is_admin
                  FROM users
                 WHERE username = %s
            """, (username,))
            row = cur.fetchone()

            if row and check_password_hash(row[2], password):
                session.update({
                    "user_id":   row[0],
                    "username":  row[1],
                    "full_name": row[3],
                    "is_admin":  row[4]
                })
                flash("Login erfolgreich!", "success")
                target = 'admin' if row[4] else 'dashboard'
                return redirect(url_for(target))
            flash("Ungültige Zugangsdaten.", "danger")
        except psycopg2.Error as e:
            print(f"Login‑DB‑Fehler: {e}")
            flash("Login fehlgeschlagen.", "danger")
        finally:
            conn.close()

    return render_template('login.html')


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session or session.get('is_admin'):
        flash("Bitte als User einloggen.", "warning")
        return redirect(url_for('login'))
    # Hier dein User‑Dashboard‑Code…
    return render_template('dashboard.html')


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
            cur = conn.cursor()
            cur.execute("""
                SELECT id, username, password_hash, full_name
                  FROM users
                 WHERE username=%s AND is_admin=TRUE
            """, (username,))
            row = cur.fetchone()
            if row and check_password_hash(row[2], password):
                session.update({
                    "user_id":        row[0],
                    "username":       row[1],
                    "full_name":      row[3],
                    "is_admin":       True,
                    "admin_logged_in": True
                })
                flash("Admin‑Login erfolgreich!", "success")
                return redirect(url_for('admin'))
            flash("Ungültige Admin‑Daten.", "danger")
        except psycopg2.Error as e:
            print(f"Admin‑Login‑DB‑Fehler: {e}")
            flash("Admin‑Login fehlgeschlagen.", "danger")
        finally:
            conn.close()

    return render_template('admin_login.html')


@app.route('/admin')
def admin():
    if not session.get('admin_logged_in'):
        flash("Nur für Admins.", "warning")
        return redirect(url_for('admin_login'))
    # Hier dein Admin‑Dashboard‑Code…
    return render_template('admin_dashboard.html')


@app.route('/logout')
def logout():
    session.clear()
    flash("Abgemeldet.", "info")
    return redirect(url_for('login'))


# (Optional: change-password / reset-password …)


# ─────────────────────  App‑Start  ──────────────────────
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
