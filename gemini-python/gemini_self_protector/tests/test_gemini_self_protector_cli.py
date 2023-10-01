from gemini_self_protector import GeminiManager
from flask import Flask

app = Flask(__name__)

gemini = GeminiManager()

@app.route("/")
@gemini.flask_protect_extended()
def hello_world():
    return "<p>Basic Config!</p>"

@app.route("/protection")
@gemini.flask_protect_extended(protect_mode='protection')
def hello_world():
    return "<p>Specific Config - Protection Mode!</p>"

@app.route("/monitor")
@gemini.flask_protect_extended(protect_mode='monitor')
def hello_world():
    return "<p>Specific Config - Monitor Mode!</p>"

@app.route("/off")
@gemini.flask_protect_extended(protect_mode='off')
def hello_world():
    return "<p>Specific Config - Off Mode!</p>"

if __name__ == '__main__':
    app.run(debug=True, port=3000)