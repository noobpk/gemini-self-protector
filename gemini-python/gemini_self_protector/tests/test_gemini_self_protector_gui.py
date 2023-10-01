from gemini_self_protector import GeminiManager
from flask import Flask

app = Flask(__name__)

gemini = GeminiManager()

@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"

if __name__ == '__main__':
    app.run(debug=True, port=3000)