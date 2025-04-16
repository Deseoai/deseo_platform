import os

# z. B. bei Render setzen: DATABASE_URL=postgres://user:pass@host:port/dbname
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:pass@localhost/deseo")
