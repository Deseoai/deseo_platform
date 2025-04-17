from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return "Hello, World!"

# Keine weiteren Initialisierungen, um zu testen, ob der Server startet
