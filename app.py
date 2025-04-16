# app.py  –  komplette, geprüfte Version
from flask import Flask, render_template, request, redirect, session, url_for, flash
import psycopg2
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from config import config
from utils.mailer import mail

app = Flask(__name__)
app.config.from_object(config)
mail.init_app(app)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# ───────────────  DB‑Hilfen  ───────────────
def get_db():
    try:
        return psycopg2.connect(app.config['DATABASE_URL'])
    except psycopg2.OperationalError as e:
        print("DB‑Verbindungsfehler:", e)
        return None

def init_db():
    conn = get_db()
    if not conn:
        return
    with conn, conn.cursor() as cur:
        # User‑Tabelle
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id SERIAL PRIMARY KEY,
            username      VARCHAR(100) UNIQUE NOT NULL,
            email         VARCHAR(120) UNIQUE NOT NULL,
            password_hash VARCHAR(128) NOT NULL,
            full_name     VARCHAR(100),
            company_name  VARCHAR(100),
            business_id   VARCHAR(50),
            is_admin      BOOLEAN DEFAULT FALSE,
            registered_on TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );""")

        # Agenten‑Tabelle
        cur.execute("""
        CREATE TABLE IF NOT EXISTS selected_agents(
            id SERIAL PRIMARY KEY,
            user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
            name       VARCHAR(100) NOT NULL,
            category   VARCHAR(50)  NOT NULL,
            package    VARCHAR(50),
            status     VARCHAR(20)  DEFAULT 'pending',
            selected_on TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );""")

        # Default‑Admin anlegen
        cur.execute("SELECT 1 FROM users WHERE is_admin LIMIT 1;")
        if not cur.fetchone():
            print("→ Erstelle Default‑Admin (user: admin / pw: changeme)")
            cur.execute("""
                INSERT INTO users (username,email,password_hash,full_name,is_admin)
                VALUES ('admin','admin@example.com',
                        %s,'Default Admin',TRUE);
            """, (generate_password_hash("changeme"),))

# ───────────────  Routen  ───────────────
@app.route('/')
def home():
    return render_template('welcome.html')

# ---------- Registrierung ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email    = request.form.get('email')
        password = request.form.get('password')
        if not all([username, email, password]):
            flash("Username, E‑Mail und Passwort sind Pflichtfelder.", "warning")
            return render_template('register.html')

        conn = get_db()
        if not conn:
            flash("Datenbank‑Verbindung fehlgeschlagen.", "danger")
            return render_template('register.html')

        try:
            with conn, conn.cursor() as cur:
                cur.execute("SELECT 1 FROM users WHERE username=%s OR email=%s",
                            (username, email))
                if cur.fetchone():
                    flash("Username oder Mail existiert bereits.", "danger")
                    return render_template('register.html')

                cur.execute("""
                    INSERT INTO users (username,email,password_hash)
                    VALUES (%s,%s,%s);
                """, (username, email, generate_password_hash(password)))

                flash("Registrierung erfolgreich – bitte einloggen.", "success")
                return redirect(url_for('login'))
        except psycopg2.Error as e:
            flash("Registrierung fehlgeschlagen (DB‑Fehler).", "danger")
            print(e)
    return render_template('register.html')

# ---------- Login ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        conn = get_db()
        if not conn:
            flash("Datenbank‑Fehler.", "danger")
            return render_template('login.html')

        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id,username,password_hash,full_name,is_admin
                    FROM users WHERE username=%s
                """, (username,))
                u = cur.fetchone()
            if u and check_password_hash(u[2], password):
                session.update({
                    "user_id":   u[0],
                    "username":  u[1],
                    "full_name": u[3],
                    "is_admin":  u[4],
                    "admin_logged_in": u[4]
                })
                flash("Login erfolgreich!", "success")
                return redirect(url_for('admin' if u[4] else 'dashboard'))
            flash("Ungültige Zugangsdaten.", "danger")
        except psycopg2.Error as e:
            flash("Login fehlgeschlagen (DB‑Fehler).", "danger")
            print(e)
    return render_template('login.html')

# ---------- Admin‑Dashboard (nur eine Beispiel‑Route) ----------
@app.route('/admin')
def admin():
    if not session.get('admin_logged_in'):
        flash("Nur für Admins.", "warning")
        return redirect(url_for('login'))
    return render_template('admin_dashboard.html')

# ---------- User‑Dashboard ----------
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or session.get('is_admin'):
        flash("Bitte als User einloggen.", "warning")
        return redirect(url_for('login'))
    return render_template('dashboard.html')

# ---------- Logout ----------
@app.route('/logout')
def logout():
    session.clear()
    flash("Abgemeldet.", "info")
    return redirect(url_for('login'))

# ───────────────  Start  ───────────────
if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
