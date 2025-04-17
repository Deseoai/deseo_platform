from flask import Flask
import os
import gunicorn.app.base

app = Flask(__name__)

@app.route('/')
def home():
    return "Hello, World!"

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
    # Umgebungsvariable PORT holen, Standard ist 8080
    port = int(os.getenv("PORT", 8080))
    options = {
        'bind': f'0.0.0.0:{port}',
        'workers': 1,
        'loglevel': 'info',
    }
    StandaloneGunicorn(app, options).run()
