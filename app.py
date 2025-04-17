from flask import Flask, render_template, request, redirect, session, url_for, flash
import psycopg2, os
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

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
    with conn.cursor() as cur:
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
        cur.execute("SELECT 1 FROM users WHERE is_admin LIMIT 1;")
        if not cur.fetchone():
            print("→ Erstelle Default‑Admin (user: admin / pw: changeme)")
            hashed = generate_password_hash("changeme")
            cur.execute("""
                INSERT INTO users (username,email,password_hash,full_name,is_admin)
                VALUES ('admin','admin@example.com',%s,'Default Admin',TRUE);
            """, (hashed,))
    conn.commit()
    conn.close()

# ─── Routen ────────────────────────────────────────────────────

@app.route('/')
def home():
    return render_template('welcome.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        u = request.form.get('username')
        e = request.form.get('email')
        p = request.form.get('password')
        if not all([u,e,p]):
            flash("Username, E‑Mail und Passwort sind Pflichtfelder.","warning")
            return render_template('register.html')
        conn = get_db()
        if not conn:
            flash("Datenbank‑Verbindung fehlgeschlagen.","danger")
            return render_template('register.html')
        try:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM users WHERE username=%s OR email=%s",(u,e))
            if cur.fetchone():
                flash("Username oder E‑Mail schon vergeben.","danger")
                return render_template('register.html')
            hashed = generate_password_hash(p)
            cur.execute("""
                INSERT INTO users(username,email,password_hash,full_name,company_name,business_id)
                VALUES(%s,%s,%s,%s,%s,%s);
            """,(u,e,hashed,
                 request.form.get('full_name'),
                 request.form.get('company_name'),
                 request.form.get('business_id')))
            conn.commit()
            flash("Registrierung erfolgreich – bitte einloggen.","success")
            return redirect(url_for('login'))
        except psycopg2.Error as err:
            print(err)
            flash("Registrierung fehlgeschlagen.","danger")
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        u = request.form.get('username')
        p = request.form.get('password')
        if not all([u,p]):
            flash("Username und Passwort erforderlich.","warning")
            return render_template('login.html')
        conn = get_db()
        if not conn:
            flash("Datenbank‑Fehler.","danger")
            return render_template('login.html')
        try:
            cur = conn.cursor()
            cur.execute("""
                SELECT id,username,password_hash,full_name,is_admin
                FROM users WHERE username=%s
            """,(u,))
            row = cur.fetchone()
            if row and check_password_hash(row[2],p):
                session.update(user_id=row[0],
                               username=row[1],
                               full_name=row[3],
                               is_admin=row[4])
                flash("Login erfolgreich!","success")
                return redirect(url_for('admin' if row[4] else 'dashboard'))
            flash("Ungültige Zugangsdaten.","danger")
        except psycopg2.Error as err:
            print(err)
            flash("Login fehlgeschlagen.","danger")
        finally:
            conn.close()
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('user_id') or session.get('is_admin'):
        flash("Bitte als User einloggen.","warning")
        return redirect(url_for('login'))
    # ... hier euer Dashboard‑Code, analog zum Admin

@app.route('/admin')
def admin():
    if not session.get('admin_logged_in'):
        flash("Nur für Admins.","warning")
        return redirect(url_for('admin_login'))
    # ... Admin‑Dashboard‑Code

@app.route('/logout')
def logout():
    session.clear()
    flash("Abgemeldet.","info")
    return redirect(url_for('login'))

# Passwort‑Änderung, Reset etc. analog ergänzen …

if __name__=="__main__":
    init_db()
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",10000)))
