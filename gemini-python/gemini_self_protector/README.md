# gemini_self_protector

Runtime Application Self-Protection

## Installation

```bash
$ pip install gemini_self_protector
```

## Protect Mode & Sensitive

Gemini supports 3 modes and recommends sensitivity levels for the application to operate at its best state.

| Mode    | Sensitive |
| ------- | --------- |
| off     | N/A       |
| monitor | 70        |
| block   | 50        |

## License Key

The license key is used for authentication with the API.

Key: `988907ce-9803-11ed-a8fc-0242ac120002`

## Basic Usage

With the basic usage, Gemini runs in the default mode of "monitor" and allows a sensitivity level of under 50, above which requests will be stored for monitoring purposes. The protection mode and sensitivity can be adjusted in the config.yml file after the first run.

```
from flask import Flask
from flask import jsonify
from flask import request

from gemini_self_protector import GeminiManager

app = Flask(__name__)
gemini = GeminiManager(license_key=os.getenv("GEMINI_LICENSE_KEY"))

@app.route('/api/login', methods=['POST'])
@gemini.flask_protect_extended()
def login():
    username = request.json['username']
    password = request.json['password']
    if username == "test" and password == "test":
        response = jsonify({
            "status": "Success",
            "message": "Login successful",
            "access_token": access_token
            })
        return response
    else:
        return jsonify({
            "status": "Fail",
            "message": "Incorrect Username or Password"
            }), 401

if __name__ == "__main__":
    app.run()
```

## Advance Usage

The advanced usage of Gemini allows for deeper customization. Specifically, it is possible to specify individual modes for each router and have a dashboard to monitor the activity of the application. The running mode and sensitivity can be adjusted directly on the dashboard, and additional features are currently being developed.

```
from flask import Flask
from flask import jsonify
from flask import request

from gemini_self_protector import GeminiManager

app = Flask(__name__)
gemini = GeminiManager(app, license_key=os.getenv("GEMINI_LICENSE_KEY"))

@app.route('/api/login', methods=['POST'])
@gemini.flask_protect_extended(protect_mode='block')
def login():
    username = request.json['username']
    password = request.json['password']
    if username == "test" and password == "test":
        response = jsonify({
            "status": "Success",
            "message": "Login successful",
            "access_token": access_token
            })
        return response
    else:
        return jsonify({
            "status": "Fail",
            "message": "Incorrect Username or Password"
            }), 401

if __name__ == "__main__":
    app.run()
```

## Contributing

Interested in contributing? Check out the contributing guidelines. Please note that this project is released with a Code of Conduct. By contributing to this project, you agree to abide by its terms.

## License

`gemini_self_protector` was created by lethanhphuc. It is licensed under the terms of the MIT license.

## Credits

`gemini_self_protector` was created with [`cookiecutter`](https://cookiecutter.readthedocs.io/en/latest/) and the `py-pkgs-cookiecutter` [template](https://github.com/py-pkgs/py-pkgs-cookiecutter).
