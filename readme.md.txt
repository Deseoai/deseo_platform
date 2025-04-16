# Deseo Voice Platform - SaaS Basis

**Features:**
- Benutzerregistrierung (User/Admin)
- Passwort-Hashing (bcrypt)
- Dashboard zur Agenten-Auswahl
- Admin-Dashboard zur Freigabe
- PostgreSQL als DB
- Dunkles Deseo-Design (Bootstrap 5)
- E-Mail vorbereitet (Flask-Mail)

**Installationsschritte:**
1. `pip install -r requirements.txt`
2. `.env.example` → `.env` umbenennen, Werte setzen (DATABASE_URL, SECRET_KEY etc.).
3. `python app.py` (oder `flask run`) lokal starten.

Auf **Render**:
- `DATABASE_URL` als Environment Variable
- **Start Command**: `python app.py`
- Optional: Email-Variablen (MAIL_SERVER etc.) für Passwort-Reset.

Viel Erfolg!
