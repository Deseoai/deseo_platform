from flask import Flask, render_template, request, redirect, session, url_for, flash
import psycopg2
import os
import bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature

from config import config
from utils.mailer import mail, send_password_reset_email

app = Flask(__name__)
app.config.from_object(config)
mail.init_app(app)

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def get_db():
    """Verbindung zur PostgreSQL DB herstellen."""
    try:
        conn = psycopg2.connect(app.config['DATABASE_URL'])
        return conn
    except psycopg2.OperationalError as e:
        print(f"DB-Verbindungsfehler: {e}")
        return None

def init_db():
    """Erstellt die erforderlichen Tabellen, falls sie nicht existieren."""
    conn = get_db()
    if not conn:
        return
    with conn.cursor() as cur:
        # Users
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            email VARCHAR(120) UNIQUE NOT NULL,
            password_hash VARCHAR(128) NOT NULL,
            full_name VARCHAR(100),
            company_name VARCHAR(100),
            business_id VARCHAR(50),
            is_admin BOOLEAN DEFAULT FALSE,
            registered_on TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """)
        # Agents
        cur.execute("""
        CREATE TABLE IF NOT EXISTS selected_agents (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            name VARCHAR(100) NOT NULL,
            category VARCHAR(50) NOT NULL,
            package VARCHAR(50),
            status VARCHAR(20) DEFAULT 'pending',
            selected_on TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """)
        conn.commit()

        # Prüfen, ob Admin existiert
        cur.execute("SELECT id FROM users WHERE is_admin = TRUE LIMIT 1;")
        admin_exists = cur.fetchone()
        if not admin_exists:
            print("Erstelle Standard-Admin (Username: admin, PW: changeme)...")
            hashed_pw = generate_password_hash("changeme").decode('utf-8')
            cur.execute("""
                INSERT INTO users (username, email, password_hash, full_name, is_admin)
                VALUES ('admin', 'admin@example.com', %s, 'Default Admin', TRUE)
            """, (hashed_pw,))
            conn.commit()
    conn.close()

class User:
    def __init__(self, id, username, email, full_name, is_admin):
        self.id = id
        self.username = username
        self.email = email
        self.full_name = full_name
        self.is_admin = is_admin

@app.route('/')
def home():
    return render_template('welcome.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name')
        company_name = request.form.get('company_name')
        business_id = request.form.get('business_id')

        if not username or not email or not password:
            flash("Username, Email, and Password are required.", "warning")
            return render_template('register.html')

        hashed_pw = generate_password_hash(password).decode('utf-8')

        conn = get_db()
        if not conn:
            flash("Database connection error.", "danger")
            return render_template('register.html')

        try:
            with conn.cursor() as cur:
                # Check ob Username/Email schon existiert
                cur.execute("SELECT id FROM users WHERE username=%s OR email=%s", (username, email))
                if cur.fetchone():
                    flash("Username or Email already taken.", "danger")
                    return render_template('register.html')

                cur.execute("""
                    INSERT INTO users (username, email, password_hash, full_name, company_name, business_id, is_admin)
                    VALUES (%s, %s, %s, %s, %s, %s, FALSE) RETURNING id
                """, (username, email, hashed_pw, full_name, company_name, business_id))
                conn.commit()

                flash("Registration successful! Please log in.", "success")
                return redirect(url_for('login'))
        except psycopg2.Error as e:
            conn.rollback()
            print(f"Fehler Registrierung: {e}")
            flash("Registration failed (DB error).", "danger")
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash("Username and Password required.", "warning")
            return render_template('login.html')

        conn = get_db()
        if not conn:
            flash("Database error.", "danger")
            return render_template('login.html')
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, username, email, password_hash, full_name, is_admin
                    FROM users
                    WHERE username = %s
                """, (username,))
                user_data = cur.fetchone()
            if user_data:
                user_id, user_name, user_email, pw_hash, full_nm, is_adm = user_data
                if check_password_hash(pw_hash, password):
                    session['user_id'] = user_id
                    session['username'] = user_name
                    session['full_name'] = full_nm
                    session['is_admin'] = is_adm
                    flash("Login successful!", "success")
                    if is_adm:
                        return redirect(url_for('admin'))
                    else:
                        return redirect(url_for('dashboard'))
                else:
                    flash("Invalid credentials.", "danger")
            else:
                flash("Invalid credentials.", "danger")
        except psycopg2.Error as e:
            print(f"Login DB error: {e}")
            flash("Login failed (DB error).", "danger")
        finally:
            conn.close()
    return render_template('login.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash("Admin username and password required.", "warning")
            return render_template('admin_login.html')

        conn = get_db()
        if not conn:
            flash("DB error.", "danger")
            return render_template('admin_login.html')
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, username, email, password_hash, full_name, is_admin
                    FROM users
                    WHERE username = %s AND is_admin = TRUE
                """, (username,))
                admin_data = cur.fetchone()

            if admin_data:
                ad_id, ad_name, ad_email, ad_hash, ad_full, ad_isadmin = admin_data
                if check_password_hash(ad_hash, password):
                    session['user_id'] = ad_id
                    session['username'] = ad_name
                    session['full_name'] = ad_full
                    session['is_admin'] = True
                    session['admin_logged_in'] = True
                    flash("Admin login successful!", "success")
                    return redirect(url_for('admin'))
                else:
                    flash("Invalid admin password.", "danger")
            else:
                flash("Admin user not found or not admin.", "danger")
        except psycopg2.Error as e:
            conn.rollback()
            print(f"Fehler Admin-Login: {e}")
            flash("Admin login failed (DB error).", "danger")
        finally:
            conn.close()

    return render_template('admin_login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session or session.get('is_admin'):
        flash("Not logged in as user.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db()
    if not conn:
        flash("DB error.", "danger")
        return render_template('dashboard.html')

    if request.method == 'POST':
        try:
            with conn.cursor() as cur:
                # Inbound
                inbound_list = request.form.getlist('inbound_agents')
                for val in inbound_list:
                    name, package = val.split('|')
                    cur.execute("""
                        INSERT INTO selected_agents (user_id, category, name, package, status)
                        VALUES (%s, 'inbound', %s, %s, 'pending')
                    """, (user_id, name, package))

                # Outbound
                outbound_list = request.form.getlist('outbound_agents')
                for agent_name in outbound_list:
                    cur.execute("""
                        INSERT INTO selected_agents (user_id, category, name, status)
                        VALUES (%s, 'outbound', %s, 'pending')
                    """, (user_id, agent_name))

                # Email Agent
                email_agent = request.form.get('email_agent')
                if email_agent:
                    cur.execute("""
                        INSERT INTO selected_agents (user_id, category, name, status)
                        VALUES (%s, 'email', %s, 'pending')
                    """, (user_id, email_agent))

                conn.commit()
                flash("Agent selection saved. Waiting for admin approval.", "success")
                return redirect(url_for('dashboard'))
        except psycopg2.Error as e:
            conn.rollback()
            print(f"Fehler Dashboard POST: {e}")
            flash("Failed to save agents.", "danger")
        finally:
            conn.close()

    # GET -> Liste Agenten
    get_conn = get_db()
    selected_agents = []
    if get_conn:
        try:
            with get_conn.cursor() as cur:
                cur.execute("""
                    SELECT name, category, package, status
                    FROM selected_agents
                    WHERE user_id=%s
                    ORDER BY selected_on DESC
                """, (user_id,))
                selected_agents = cur.fetchall()
        except psycopg2.Error as e:
            print(f"Fehler Dashboard GET: {e}")
            flash("Could not load your agents.", "warning")
        finally:
            get_conn.close()

    return render_template('dashboard.html',
                           greeting_name=session.get('full_name', session.get('username')),
                           selected_agents=selected_agents)

@app.route('/admin')
def admin():
    if not session.get('admin_logged_in'):
        flash("Admin only.", "warning")
        return redirect(url_for('admin_login'))

    conn = get_db()
    agents_list = []
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT a.id, u.username, u.full_name, a.name, a.category, a.package, a.status
                    FROM selected_agents a
                    JOIN users u ON a.user_id = u.id
                    ORDER BY a.selected_on DESC
                """)
                agents_list = cur.fetchall()
        except psycopg2.Error as e:
            print(f"Fehler Admin: {e}")
            flash("Failed to load agent requests.", "danger")
        finally:
            conn.close()

    return render_template('admin_dashboard.html', agents=agents_list)

@app.route('/admin/users')
def admin_users():
    if not session.get('admin_logged_in'):
        flash("Admin only.", "warning")
        return redirect(url_for('admin_login'))

    conn = get_db()
    users_list = []
    if conn:
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, username, email, full_name, company_name, business_id, is_admin, registered_on
                    FROM users
                    ORDER BY id ASC
                """)
                users_list = cur.fetchall()
        except psycopg2.Error as e:
            print(f"Fehler Admin Users: {e}")
            flash("Failed to load users list.", "danger")
        finally:
            conn.close()

    return render_template('admin_users.html', users=users_list)

@app.route('/admin/activate/<int:agent_id>', methods=['POST'])
def activate_agent(agent_id):
    if not session.get('admin_logged_in'):
        flash("Admin only.", "warning")
        return redirect(url_for('admin_login'))

    conn = get_db()
    if not conn:
        flash("DB error.", "danger")
        return redirect(url_for('admin'))

    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE selected_agents SET status='active' WHERE id=%s RETURNING user_id", (agent_id,))
            result = cur.fetchone()
            conn.commit()
            if result:
                flash(f"Agent {agent_id} activated.", "success")
            else:
                flash(f"Agent {agent_id} not found.", "warning")
    except psycopg2.Error as e:
        conn.rollback()
        print(f"Fehler Activation: {e}")
        flash("Activation DB error.", "danger")
    finally:
        conn.close()
    return redirect(url_for('admin'))

# --- Passwort-Reset Routen (optional) ---
@app.route('/request_password_reset', methods=['GET', 'POST'])
def request_password_reset():
    return render_template('request_password_reset.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    return render_template('reset_password.html')

if __name__ == "__main__":
    with app.app_context():
        init_db()
    port = int(os.environ.get('PORT', 10000))
    app.run(host="0.0.0.0", port=port)
