import os
import psycopg2
from flask import (
    Flask, render_template, request, redirect,
    session, url_for, flash
)
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
        print("Datenbankinit abgebrochen.")
        return
    try:
        with conn:
            with conn.cursor() as cur:
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
                    print("→ Default‑Admin anlegen")
                    cur.execute("""
                        INSERT INTO users(username,email,password_hash,full_name,is_admin)
                        VALUES('admin','admin@example.com',%s,'Default Admin',TRUE);
                    """, (generate_password_hash("changeme"),))
    except Exception as e:
        print(f"Init-Fehler: {e}")
    finally:
        conn.close()

@app.route('/')
def home():
    return render_template('welcome.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        u=request.form
        if not all([u.get('username'), u.get('email'), u.get('password')]):
            flash("Username, E‑Mail, Passwort erforderlich.", "warning")
            return render_template('register.html')
        conn=get_db()
        if not conn:
            flash("DB‑Verbindung fehlgeschlagen.", "danger")
            return render_template('register.html')
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1 FROM users WHERE username=%s OR email=%s",
                                (u['username'],u['email']))
                    if cur.fetchone():
                        flash("Username oder E‑Mail existiert.", "danger")
                        return render_template('register.html')
                    cur.execute("""
                        INSERT INTO users(username,email,password_hash,full_name,company_name,business_id)
                        VALUES(%s,%s,%s,%s,%s,%s);
                    """,(
                        u['username'],u['email'],
                        generate_password_hash(u['password']),
                        u.get('full_name'),
                        u.get('company_name'),
                        u.get('business_id')
                    ))
            flash("Erfolgreich registriert – bitte einloggen.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash("Registrierung fehlgeschlagen.", "danger")
            print(e)
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method=='POST':
        u=request.form
        if not u.get('username') or not u.get('password'):
            flash("Username und Passwort erforderlich.", "warning")
            return render_template('login.html')
        conn=get_db()
        if not conn:
            flash("DB‑Fehler.", "danger")
            return render_template('login.html')
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id,username,password_hash,full_name,is_admin
                    FROM users WHERE username=%s
                """,(u['username'],))
                row=cur.fetchone()
            if row and check_password_hash(row[2],u['password']):
                session.update({
                    'user_id':row[0],'username':row[1],
                    'full_name':row[3],'is_admin':row[4]
                })
                flash("Login erfolgreich!", "success")
                return redirect(
                    url_for('admin') if row[4] else url_for('dashboard')
                )
            flash("Ungültige Zugangsdaten.", "danger")
        except Exception as e:
            flash("Login DB‑Fehler.", "danger")
            print(e)
        finally:
            conn.close()
    return render_template('login.html')

@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if request.method=='POST':
        u=request.form
        conn=get_db()
        if not conn:
            flash("DB‑Fehler.", "danger")
            return render_template('admin_login.html')
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id,username,password_hash,full_name
                    FROM users WHERE username=%s AND is_admin=TRUE
                """,(u['username'],))
                row=cur.fetchone()
            if row and check_password_hash(row[2],u['password']):
                session.update({
                    'user_id':row[0],'username':row[1],
                    'full_name':row[3],'is_admin':True,
                    'admin_logged_in':True
                })
                flash("Admin‑Login OK!", "success")
                return redirect(url_for('admin'))
            flash("Ungültige Admin‑Daten.", "danger")
        except Exception as e:
            flash("Admin‑Login DB‑Fehler.", "danger")
            print(e)
        finally:
            conn.close()
    return render_template('admin_login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Abgemeldet.", "info")
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET','POST'])
def dashboard():
    if 'user_id' not in session or session.get('is_admin'):
        flash("Bitte als User einloggen.", "warning")
        return redirect(url_for('login'))
    uid=session['user_id']
    if request.method=='POST':
        conn=get_db()
        if conn:
            try:
                with conn:
                    with conn.cursor() as cur:
                        for val in request.form.getlist('inbound_agents'):
                            n,p=val.split('|')
                            cur.execute("""
                                INSERT INTO selected_agents(user_id,category,name,package,status)
                                VALUES(%s,'inbound',%s,%s,'pending')
                            """,(uid,n,p))
                        for nm in request.form.getlist('outbound_agents'):
                            cur.execute("""
                                INSERT INTO selected_agents(user_id,category,name,status)
                                VALUES(%s,'outbound',%s,'pending')
                            """,(uid,nm))
                        m=request.form.get('email_agent')
                        if m:
                            cur.execute("""
                                INSERT INTO selected_agents(user_id,category,name,status)
                                VALUES(%s,'email',%s,'pending')
                            """,(uid,m))
                flash("Auswahl gespeichert.", "success")
            except Exception as e:
                flash("Speichern fehlgeschlagen.", "danger")
                print(e)
            finally:
                conn.close()
        return redirect(url_for('dashboard'))
    conn2=get_db()
    sel=[]
    if conn2:
        with conn2.cursor() as cur:
            cur.execute("""
                SELECT name,category,package,status
                FROM selected_agents WHERE user_id=%s ORDER BY selected_on DESC
            """,(uid,))
            sel=cur.fetchall()
        conn2.close()
    return render_template('dashboard.html',
                           greeting_name=session.get('full_name'),
                           selected_agents=sel)

@app.route('/admin')
def admin():
    if not session.get('admin_logged_in'):
        flash("Nur Admins.", "warning")
        return redirect(url_for('admin_login'))
    conn=get_db(); ag=[]
    if conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT a.id,u.username,u.full_name,
                       a.name,a.category,a.package,a.status
                FROM selected_agents a
                JOIN users u ON a.user_id=u.id
                ORDER BY a.selected_on DESC
            """)
            ag=cur.fetchall()
        conn.close()
    return render_template('admin_dashboard.html', agents=ag)

@app.route('/admin/users')
def admin_users():
    if not session.get('admin_logged_in'):
        flash("Nur Admins.", "warning")
        return redirect(url_for('admin_login'))
    conn=get_db(); us=[]
    if conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id,username,email,full_name,
                       company_name,business_id,is_admin,registered_on
                FROM users ORDER BY id
            """)
            us=cur.fetchall()
        conn.close()
    return render_template('admin_users.html', users=us)

@app.route('/admin/activate/<int:agent_id>', methods=['POST'])
def activate_agent(agent_id):
    if not session.get('admin_logged_in'):
        flash("Nur Admins.", "warning")
        return redirect(url_for('admin_login'))
    conn=get_db()
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
        flash("DB‑Fehler.", "danger")
    return redirect(url_for('admin'))

@app.route('/change-password', methods=['GET','POST'])
def change_password():
    if 'user_id' not in session:
        flash("Bitte einloggen.", "warning")
        return redirect(url_for('login'))
    if request.method=='POST':
        f=request.form
        if not all([f.get('current_password'),f.get('new_password'),f.get('repeat_password')]):
            flash("Alle Felder ausfüllen.", "warning"); return render_template('change_password.html')
        if f['new_password']!=f['repeat_password']:
            flash("Neue Passwörter unterschiedlich.", "danger"); return render_template('change_password.html')
        conn=get_db()
        if conn:
            with conn.cursor() as cur:
                cur.execute("SELECT password_hash FROM users WHERE id=%s",(session['user_id'],))
                h=cur.fetchone()[0]
            if not check_password_hash(h,f['current_password']):
                flash("Aktuelles Passwort falsch.", "danger"); conn.close(); return render_template('change_password.html')
            with conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE users SET password_hash=%s WHERE id=%s",
                                (generate_password_hash(f['new_password']),session['user_id']))
            conn.close()
        flash("Passwort geändert.", "success")
        return redirect(url_for('admin' if session.get('is_admin') else 'dashboard'))
    return render_template('change_password.html')

@app.route('/request-password-reset', methods=['GET','POST'])
def request_password_reset():
    if request.method=='POST':
        e=request.form.get('email')
        if not e:
            flash("E‑Mail erforderlich.", "warning"); return render_template('request_password_reset.html')
        conn=get_db()
        if not conn:
            flash("DB‑Fehler.", "danger"); return render_template('request_password_reset.html')
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT id,username,email,full_name FROM users WHERE email=%s",(e,))
                usr=cur.fetchone()
            if usr:
                token=serializer.dumps(e,salt='password-reset-salt')
                send_password_reset_email(
                    {'id':usr[0],'username':usr[1],'email':usr[2],'full_name':usr[3]},
                    token
                )
                flash("Reset‑Link gesendet.", "success")
            else:
                flash("E‑Mail nicht gefunden.", "danger")
        except Exception as ex:
            flash("Fehler.", "danger"); print(ex)
        finally:
            conn.close()
        return redirect(url_for('login'))
    return render_template('request_password_reset.html')

@app.route('/reset-password/<token>', methods=['GET','POST'])
def reset_password(token):
    try:
        e=serializer.loads(token,salt='password-reset-salt',
                          max_age=app.config['PASSWORD_RESET_TOKEN_MAX_AGE'])
    except Exception as ex:
        flash("Link ungültig/abgelaufen.", "danger"); print(ex); return redirect(url_for('request_password_reset'))
    if request.method=='POST':
        f=request.form
        if not f.get('password') or not f.get('confirm_password'):
            flash("Alle Felder.", "warning"); return render_template('reset_password.html')
        if f['password']!=f['confirm_password']:
            flash("Nicht gleich.", "danger"); return render_template('reset_password.html')
        conn=get_db()
        if not conn:
            flash("DB‑Fehler.", "danger"); return render_template('reset_password.html')
        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("UPDATE users SET password_hash=%s WHERE email=%s",
                                (generate_password_hash(f['password']),e))
            flash("Passwort zurückgesetzt.", "success")
            return redirect(url_for('login'))
        except Exception as ex:
            flash("Fehler.", "danger"); print(ex)
        finally:
            conn.close()
    return render_template('reset_password.html')

if __name__=='__main__':
    with app.app_context():
        init_db()
    port=int(os.environ.get('PORT',10000))
    app.run(host='0.0.0.0',port=port)
