import os

# URL deiner PostgreSQL-Datenbank
# Render setzt diese automatisch als Umgebungsvariable (Environment Variable)
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost/deseo")
