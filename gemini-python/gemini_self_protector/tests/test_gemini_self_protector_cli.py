from gemini_self_protector import GeminiManager
from flask import Flask

app = Flask(__name__)

gemini = GeminiManager()


@app.route("/")
@gemini.flask_protect_extended()
def index():
    return "<p>Running gemini-self protector - CLI Mode!</p>"


@app.route("/protection")
@gemini.flask_protect_extended(protect_mode='protection')
def protection_mode():
    return "<p>Protect mode - Protection!</p>"


@app.route("/monitor")
@gemini.flask_protect_extended(protect_mode='monitor')
def monitor_mode():
    return "<p>Protect mode - Monitor!</p>"


@app.route("/off")
@gemini.flask_protect_extended(protect_mode='off')
def off_mode():
    return "<p>Protect mode - Off!</p>"

if __name__ == '__main__':
    app.run(debug=True, port=3000)