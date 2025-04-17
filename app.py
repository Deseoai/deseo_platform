import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import gunicorn.app.base

app = Flask(__name__)
app.config.from_object('config.Config')
csrf = CSRFProtect(app)
mail = Mail(app)

# Konfiguriere Flask-Limiter mit In-Memory-Speicher
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Initialisiere Connection Pool
db_pool = ConnectionPool(
    conninfo=app.config['DATABASE_URL'],
    min_size=1,
    max_size=10,
    open=True
)

# Datenbankverbindung aus dem Pool holen
def get_db_connection():
    if 'db_conn' not in g:
        g.db_conn = db_pool.getconn()
        g.db_conn.row_factory = dict_row
    return g.db_conn

# Verbindung nach dem Request zurückgeben
@app.teardown_appcontext
def close_db_connection(exception):
    conn = g.pop('db_conn', None)
    if conn is not None:
        db_pool.putconn(conn)

# Error-Handler für 404
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# Error-Handler für 500
@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Startseite
@app.route('/')
def home():
    return render_template('welcome.html')

# Benutzer-Login
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if session.get('user_id'):
        if session.get('is_admin'):
            return redirect(url_for('admin'))
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('login'))
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('SELECT id, username, password_hash, is_admin FROM users WHERE username = %s', (username,))
            user = cur.fetchone()
            cur.close()
            
            if user and check_password_hash(user['password_hash'], password):
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['is_admin'] = user['is_admin']
                if user['is_admin']:
                    flash('Admin login successful!', 'success')
                    return redirect(url_for('admin'))
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'danger')
        except Exception as e:
            flash('An error occurred. Please try again later.', 'danger')
            if app.config['DEBUG']:
                app.logger.error(f"Login error: {str(e)}")
    
    return render_template('login.html')

# Admin-Login
@app.route('/admin/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=["POST"])
def admin_login():
    if session.get('user_id') and session.get('is_admin'):
        return redirect(url_for('admin'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('admin_login'))
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('SELECT id, username, password_hash, is_admin FROM users WHERE username = %s AND is_admin = true', (username,))
            admin = cur.fetchone()
            cur.close()
            
            if admin and check_password_hash(admin['password_hash'], password):
                session['user_id'] = admin['id']
                session['username'] = admin['username']
                session['is_admin'] = admin['is_admin']
                flash('Admin login successful!', 'success')
                return redirect(url_for('admin'))
            else:
                flash('Invalid admin credentials.', 'danger')
        except Exception as e:
            flash('An error occurred. Please try again later.', 'danger')
            if app.config['DEBUG']:
                app.logger.error(f"Admin login error: {str(e)}")
    
    return render_template('admin_login.html')

# Registrierung
@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def register():
    if session.get('user_id'):
        if session.get('is_admin'):
            return redirect(url_for('admin'))
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name') or None
        company_name = request.form.get('company_name') or None
        business_id = request.form.get('business_id') or None
        
        if not username or not email or not password:
            flash('Username, email, and password are required.', 'danger')
            return redirect(url_for('register'))
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('SELECT id FROM users WHERE username = %s OR email = %s', (username, email))
            existing_user = cur.fetchone()
            
            if existing_user:
                cur.close()
                flash('Username or email already exists.', 'danger')
                return redirect(url_for('register'))
            
            password_hash = generate_password_hash(password)
            cur.execute(
                'INSERT INTO users (username, email, password_hash, full_name, company_name, business_id, is_admin) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id',
                (username, email, password_hash, full_name, company_name, business_id, False)
            )
            user_id = cur.fetchone()['id']
            conn.commit()
            cur.close()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('An error occurred during registration. Please try again later.', 'danger')
            if app.config['DEBUG']:
                app.logger.error(f"Registration error: {str(e)}")
    
    return render_template('register.html')

# Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if not session.get('user_id'):
        flash('Please log in to access the dashboard.', 'danger')
        return redirect(url_for('login'))
    
    if session.get('is_admin'):
        return redirect(url_for('admin'))
    
    greeting_name = session.get('username')
    selected_agents = []
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        # Kombinierte Abfrage für bessere Performance
        cur.execute('''
            SELECT u.full_name, a.id, a.name, a.category, a.package, a.status
            FROM users u
            LEFT JOIN agents a ON a.user_id = u.id
            WHERE u.id = %s
        ''', (session['user_id'],))
        results = cur.fetchall()
        
        if results:
            greeting_name = results[0]['full_name'] or greeting_name
            selected_agents = [
                {'id': r['id'], 'name': r['name'], 'category': r['category'], 'package': r['package'], 'status': r['status']}
                for r in results if r['id'] is not None
            ]
        
        if request.method == 'POST':
            inbound_agents = request.form.getlist('inbound_agents')
            outbound_agents = request.form.getlist('outbound_agents')
            email_agent = request.form.get('email_agent')
            
            agents_to_insert = []
            for agent in inbound_agents:
                name, package = agent.split('|')
                agents_to_insert.append((name, 'inbound', package))
            for agent in outbound_agents:
                agents_to_insert.append((agent, 'outbound', None))
            if email_agent:
                agents_to_insert.append((email_agent, 'email', None))
            
            for name, category, package in agents_to_insert:
                cur.execute(
                    'INSERT INTO agents (user_id, name, category, package, status) VALUES (%s, %s, %s, %s, %s)',
                    (session['user_id'], name, category, package, 'pending')
                )
            conn.commit()
            flash('Agent selection submitted successfully!', 'success')
            return redirect(url_for('dashboard'))
        
        cur.close()
    except Exception as e:
        flash('An error occurred while loading the dashboard. Please try again later.', 'danger')
        if app.config['DEBUG']:
            app.logger.error(f"Dashboard error: {str(e)}")
    
    return render_template('dashboard.html', greeting_name=greeting_name, selected_agents=selected_agents)

# Profilseite
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if not session.get('user_id'):
        flash('Please log in to access your profile.', 'danger')
        return redirect(url_for('login'))
    
    if session.get('is_admin'):
        return redirect(url_for('admin'))
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if request.method == 'POST':
            full_name = request.form.get('full_name') or None
            company_name = request.form.get('company_name') or None
            business_id = request.form.get('business_id') or None
            
            cur.execute(
                'UPDATE users SET full_name = %s, company_name = %s, business_id = %s WHERE id = %s',
                (full_name, company_name, business_id, session['user_id'])
            )
            conn.commit()
            flash('Profile updated successfully!', 'success')
            return redirect(url_for('profile'))
        
        cur.execute(
            'SELECT username, email, full_name, company_name, business_id FROM users WHERE id = %s',
            (session['user_id'],)
        )
        user = cur.fetchone()
        cur.close()
        
        if not user:
            flash('Unable to load profile. Please try again later.', 'danger')
            return redirect(url_for('dashboard'))
        
        return render_template('profile.html', user=user)
    except Exception as e:
        flash('An error occurred while loading your profile. Please try again later.', 'danger')
        if app.config['DEBUG']:
            app.logger.error(f"Profile error: {str(e)}")
        return redirect(url_for('dashboard'))

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

# Passwort ändern
@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if not session.get('user_id'):
        flash('Please log in to change your password.', 'danger')
        return redirect(url_for('login'))
    
    if session.get('is_admin'):
        return redirect(url_for('admin'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        repeat_password = request.form.get('repeat_password')
        
        if not current_password or not new_password or not repeat_password:
            flash('All fields are required.', 'danger')
            return redirect(url_for('change_password'))
        
        if new_password != repeat_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('change_password'))
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('SELECT password_hash FROM users WHERE id = %s', (session['user_id'],))
            user = cur.fetchone()
            
            if not user or not check_password_hash(user['password_hash'], current_password):
                cur.close()
                flash('Current password is incorrect.', 'danger')
                return redirect(url_for('change_password'))
            
            new_password_hash = generate_password_hash(new_password)
            cur.execute('UPDATE users SET password_hash = %s WHERE id = %s', (new_password_hash, session['user_id']))
            conn.commit()
            cur.close()
            
            flash('Password changed successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash('An error occurred while changing your password. Please try again later.', 'danger')
            if app.config['DEBUG']:
                app.logger.error(f"Change password error: {str(e)}")
    
    return render_template('change_password.html')

# Passwort-Reset anfordern
@app.route('/request-password-reset', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def request_password_reset():
    if session.get('user_id'):
        if session.get('is_admin'):
            return redirect(url_for('admin'))
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        
        if not email:
            flash('Email is required.', 'danger')
            return redirect(url_for('request_password_reset'))
        
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('SELECT id, username FROM users WHERE email = %s', (email,))
            user = cur.fetchone()
            
            if user:
                token = secrets.token_urlsafe(32)
                expires_at = datetime.utcnow().timestamp() + app.config['PASSWORD_RESET_TOKEN_MAX_AGE']
                cur.execute(
                    'INSERT INTO password_resets (user_id, token, expires_at) VALUES (%s, %s, %s)',
                    (user['id'], token, expires_at)
                )
                conn.commit()
                
                reset_link = url_for('reset_password', token=token, _external=True)
                msg = Message(
                    'Password Reset Request',
                    recipients=[email],
                    body=f'Hello {user["username"]},\n\nTo reset your password, click the following link: {reset_link}\n\nThis link will expire in 1 hour.\n\nIf you did not request a password reset, please ignore this email.\n\nBest regards,\nDeseo Team'
                )
                mail.send(msg)
                flash('A password reset link has been sent to your email.', 'success')
            else:
                flash('No account found with that email address.', 'danger')
            
            cur.close()
        except Exception as e:
            flash('An error occurred while processing your request. Please try again later.', 'danger')
            if app.config['DEBUG']:
                app.logger.error(f"Password reset request error: {str(e)}")
    
    return render_template('request_password_reset.html')

# Passwort zurücksetzen
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=["POST"])
def reset_password(token):
    if session.get('user_id'):
        if session.get('is_admin'):
            return redirect(url_for('admin'))
        return redirect(url_for('dashboard'))
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        current_time = datetime.utcnow().timestamp()
        cur.execute(
            'SELECT user_id FROM password_resets WHERE token = %s AND expires_at > %s',
            (token, current_time)
        )
        reset_request = cur.fetchone()
        
        if not reset_request:
            cur.close()
            flash('Invalid or expired password reset token.', 'danger')
            return redirect(url_for('request_password_reset'))
        
        if request.method == 'POST':
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            if not password or not confirm_password:
                flash('Both fields are required.', 'danger')
                return redirect(url_for('reset_password', token=token))
            
            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return redirect(url_for('reset_password', token=token))
            
            password_hash = generate_password_hash(password)
            cur.execute('UPDATE users SET password_hash = %s WHERE id = %s', (password_hash, reset_request['user_id']))
            cur.execute('DELETE FROM password_resets WHERE token = %s', (token,))
            conn.commit()
            cur.close()
            
            flash('Your password has been reset successfully. Please log in.', 'success')
            return redirect(url_for('login'))
        
        cur.close()
    except Exception as e:
        flash('An error occurred while resetting your password. Please try again later.', 'danger')
        if app.config['DEBUG']:
            app.logger.error(f"Password reset error: {str(e)}")
        return redirect(url_for('request_password_reset'))
    
    return render_template('reset_password.html')

# Admin-Dashboard
@app.route('/admin', methods=['GET'])
def admin():
    if not session.get('user_id') or not session.get('is_admin'):
        flash('Please log in as an admin to access this page.', 'danger')
        return redirect(url_for('admin_login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM agents')
        total_agents = cur.fetchone()['count']
        total_pages = (total_agents + per_page - 1) // per_page
        
        cur.execute('''
            SELECT a.id, u.username, u.full_name, a.name, a.category, a.package, a.status
            FROM agents a
            JOIN users u ON a.user_id = u.id
            ORDER BY a.status, u.username
            LIMIT %s OFFSET %s
        ''', (per_page, offset))
        agents = cur.fetchall()
        cur.close()
        return render_template(
            'admin_dashboard.html',
            agents=agents,
            page=page,
            total_pages=total_pages,
            per_page=per_page
        )
    except psycopg.Error as e:
        if "relation \"agents\" does not exist" in str(e):
            flash('The agents table is missing in the database. Please contact support.', 'danger')
        else:
            flash('An error occurred while loading the admin dashboard. Please try again later.', 'danger')
            if app.config['DEBUG']:
                app.logger.error(f"Admin dashboard error: {str(e)}")
        return redirect(url_for('admin_login'))

# Benutzerübersicht (Admin)
@app.route('/admin/users', methods=['GET'])
def admin_users():
    if not session.get('user_id') or not session.get('is_admin'):
        flash('Please log in as an admin to access this page.', 'danger')
        return redirect(url_for('admin_login'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT COUNT(*) FROM users')
        total_users = cur.fetchone()['count']
        total_pages = (total_users + per_page - 1) // per_page
        
        cur.execute('''
            SELECT id, username, email, full_name, company_name, business_id, is_admin, created_at
            FROM users
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        ''', (per_page, offset))
        users = cur.fetchall()
        cur.close()
        return render_template(
            'admin_users.html',
            users=users,
            page=page,
            total_pages=total_pages,
            per_page=per_page
        )
    except Exception as e:
        flash('An error occurred while loading the user list. Please try again later.', 'danger')
        if app.config['DEBUG']:
            app.logger.error(f"Admin users error: {str(e)}")
        return redirect(url_for('admin'))

# Agent aktivieren (Admin)
@app.route('/admin/activate/<int:agent_id>', methods=['POST'])
def activate_agent(agent_id):
    if not session.get('user_id') or not session.get('is_admin'):
        flash('Please log in as an admin to perform this action.', 'danger')
        return redirect(url_for('admin_login'))
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('UPDATE agents SET status = %s WHERE id = %s AND status = %s', ('active', agent_id, 'pending'))
        conn.commit()
        if cur.rowcount == 0:
            flash('Agent not found or already activated.', 'warning')
        else:
            flash('Agent activated successfully!', 'success')
        cur.close()
    except Exception as e:
        flash('An error occurred while activating the agent. Please try again later.', 'danger')
        if app.config['DEBUG']:
            app.logger.error(f"Agent activation error: {str(e)}")
    
    return redirect(url_for('admin'))

# Benutzer löschen (Admin)
@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('user_id') or not session.get('is_admin'):
        flash('Please log in as an admin to perform this action.', 'danger')
        return redirect(url_for('admin_login'))
    
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_users'))
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('DELETE FROM agents WHERE user_id = %s', (user_id,))
        cur.execute('DELETE FROM password_resets WHERE user_id = %s', (user_id,))
        cur.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        if cur.rowcount == 0:
            flash('User not found.', 'warning')
        else:
            flash('User deleted successfully!', 'success')
        cur.close()
    except Exception as e:
        flash('An error occurred while deleting the user. Please try again later.', 'danger')
        if app.config['DEBUG']:
            app.logger.error(f"Delete user error: {str(e)}")
    
    return redirect(url_for('admin_users'))

# Agent löschen
@app.route('/delete-agent/<int:agent_id>', methods=['POST'])
def delete_agent(agent_id):
    if not session.get('user_id'):
        flash('Please log in to perform this action.', 'danger')
        return redirect(url_for('login'))
    
    if session.get('is_admin'):
        return redirect(url_for('admin'))
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('DELETE FROM agents WHERE id = %s AND user_id = %s AND status = %s', (agent_id, session['user_id'], 'pending'))
        conn.commit()
        if cur.rowcount == 0:
            flash('Agent not found or cannot be deleted.', 'warning')
        else:
            flash('Agent deleted successfully!', 'success')
        cur.close()
    except Exception as e:
        flash('An error occurred while deleting the agent. Please try again later.', 'danger')
        if app.config['DEBUG']:
            app.logger.error(f"Delete agent error: {str(e)}")
    
    return redirect(url_for('dashboard'))

# Gunicorn-Server direkt starten
class StandaloneGunicorn(gunicorn.app.base.BaseApplication):
    def __init__(self, app, options=None):
        self.options = options or {}
        self.application = app
        super().__init__()

    def load_config(self):
        for key, value in self.options.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application

if __name__ == '__main__':
    port = int(os.getenv("PORT", 8080))
    options = {
        'bind': f'0.0.0.0:{port}',
        'workers': 3,
        'loglevel': 'error',
        'timeout': 60,
    }
    StandaloneGunicorn(app, options).run()
