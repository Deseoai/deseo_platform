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


# ---------- Hilfsfunktionen ----------
def get_db():
    """Verbindung zur PostgreSQL‑DB herstellen (liefert None bei Fehler)."""
    try:
        return psycopg2.connect(app.config['DATABASE_URL'])
    except psycopg2.OperationalError as e:
        print(f"DB‑Verbindungsfehler: {e}")
        return None


def init_db():
    """Tabellen anlegen + Default‑Admin erzeugen (falls nötig)."""
    conn = get_db()
    if not conn:
        return

    with conn, conn.cursor() as cur:
        # users‑Tabelle
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

        # selected_agents‑Tabelle
        cur.execute("""
        CREATE TABLE IF NOT EXISTS selected_agents(
            id SERIAL PRIMARY KEY,
            user_id   INTEGER REFERENCES users(id) ON DELETE CASCADE,
            name      VARCHAR(100) NOT NULL,
            category  VARCHAR(50)  NOT NULL,
            package   VARCHAR(50),
            status    VARCHAR(20)  DEFAULT 'pending',
            selected_on TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        );""")

        # Default‑Admin anlegen (einmalig)
        cur.execute("SELECT 1 FROM users WHERE is_admin LIMIT 1;")
        if not cur.fetchone():
            print("→ Kein Admin gefunden – lege Standard‑Admin an (user: admin / pw: changeme)")
            hashed_pw = generate_password_hash("changeme")       #  ← .decode entfernt
            cur.execute("""
                INSERT INTO users (username, email, password_hash, full_name, is_admin)
                VALUES ('admin', 'admin@example.com', %s, 'Default Admin', TRUE);
            """, (hashed_pw,))


# ---------- Routen ----------
@app.route('/')
def home():
    return render_template('welcome.html')


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
            flash("Username, E‑Mail und Passwort sind Pflichtfelder.", "warning")
            return render_template('register.html')

        hashed_pw = generate_password_hash(password)            #  ← .decode entfernt
        conn = get_db()
        if not conn:
            flash("Datenbank‑Verbindungsfehler.", "danger")
            return render_template('register.html')

        try:
            with conn, conn.cursor() as cur:
                cur.execute("SELECT 1 FROM users WHERE username=%s OR email=%s", (username, email))
                if cur.fetchone():
                    flash("Username oder Mail existiert bereits.", "danger")
                    return render_template('register.html')

                cur.execute("""
                    INSERT INTO users (username, email, password_hash,
                                       full_name, company_name, business_id)
                    VALUES (%s,%s,%s,%s,%s,%s);""",
                    (username, email, hashed_pw, full_name, company_name, business_id))
                flash("Registrierung erfolgreich – bitte einloggen.", "success")
                return redirect(url_for('login'))
        except psycopg2.Error as e:
            flash("Registrierung fehlgeschlagen (DB‑Fehler).", "danger")
            print(e)
        finally:
            conn.close()

    return render_template('register.html')


# ---------- (alle übrigen Routen bleiben wie gehabt) ----------
# ...   (gekürzt, weil dort keine Änderung nötig war)   ...


if __name__ == "__main__":
    with app.app_context():
        init_db()
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
