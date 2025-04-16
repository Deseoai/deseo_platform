import os

# Hole die Datenbankverbindung aus der Umgebungsvariable
DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL is not set. Please define it as an environment variable.")
