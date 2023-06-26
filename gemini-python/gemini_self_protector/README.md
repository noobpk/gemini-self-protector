# gemini_self_protector

Gemini - The Runtime Application Self Protection (RASP) Solution Combined With Deep Learning

## Installation

```
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

## Init Gemini self-protector

### CLI Mode

```
from flask import Flask, request
from gemini_self_protector import GeminiManager

app = Flask(__name__)
gemini = GeminiManager()
```

### GUI Mode

```
from flask import Flask, request
from gemini_self_protector import GeminiManager

app = Flask(__name__)
gemini = GeminiManager(app)
```

## Basic Usage

With the basic usage, Gemini runs in the default mode of "monitoring" and allows a sensitivity level of under 50, above which requests will be stored for monitoring purposes.

```
from flask import Flask, request, jsonify
from gemini_self_protector import GeminiManager

app = Flask(__name__)
gemini = GeminiManager(app)

@app.route('/api/login', methods=['POST'])
@gemini.flask_protect_extended() <--- Declare gemini below flask route and without option
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
gemini = GeminiManager(app)

@app.route('/api/login', methods=['POST'])
@gemini.flask_protect_extended(protect_mode='block') <--- Declare gemini below flask route with protect mode option
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

## Gemini Protect Against

| Attacks                 | Supported          |
| ----------------------- | ------------------ |
| Malformed Content Types |                    |
| HTTP Method Tampering   | :white_check_mark: |
| Large Requests          | :white_check_mark: |
| Path Traversal          |                    |
| Unvalidated Redirects   | :white_check_mark: |

| Injections                 | Supported          |
| -------------------------- | ------------------ |
| Command Injection          | :white_check_mark: |
| Cross-Site Scripting       | :white_check_mark: |
| Cross-Site Request Forgery |                    |
| CSS & HTML Injection       |                    |
| JSON & XML Injection       |                    |
| SQL Injection              | :white_check_mark: |

| Weaknesses                   | Supported          |
| ---------------------------- | ------------------ |
| Insecure Cookies & Transport |                    |
| Weak Browser Caching         | :white_check_mark: |
| Vulnerable Dependencies      | :white_check_mark: |
| Weak Cryptography            |                    |
| HTTP Response Headers        | :white_check_mark: |
| API Rate Limit               | :white_check_mark: |

## Gemini Security Response Headers

| HTTP Response Headers | Default configuration | 
| ------------------------------ | --------------------- |
| X-Frame-Options                | SAMEORIGIN            |
| X-XSS-Protection               | 1; mode=block         |
| X-Content-Type-Options         | nosniff               |
| Referrer-Policy                | no-referrer-when-downgrade |
| Content-Type                   | N/A                   |
| Strict-Transport-Security      | max-age=31536000; includeSubDomains; preload |
| Expect-CT                      | enforce; max-age=31536000 |
| Content-Security-Policy        | N/A                   |
| X-Permitted-Cross-Domain-Policies | none               |
| Feature-Policy                 | fullscreen 'self'     |
| Cache-Control                  | no-cache, no-store, must-revalidate |
| Pragma                         | no-cache              |
| Expires                        | 0                     |
| X-UA-Compatible                | IE=Edge,chrome=1      |
| Access-Control-Allow-Origin    | *                     |
| Access-Control-Allow-Methods   | *                     |
| Access-Control-Allow-Headers   | *                     |
| Access-Control-Allow-Credentials | true                |
| Cross-Origin-Opener-Policy     | N/A                   |
| Cross-Origin-Embedder-Policy   | N/A                   |
| Cross-Origin-Resource-Policy   | N/A                   |
| Permissions-Policy             | N/A                   |
| FLoC                           | N/A                   |
| Server                         | gemini                |
| X-Powered-By                   | N/A                   |
| X-AspNet-Version               | N/A                   |
| X-AspNetMvc-Version            | N/A                   |
| X-DNS-Prefetch-Control         | N/A                   |

## Contributing

Interested in contributing? Check out the contributing guidelines. Please note that this project is released with a Code of Conduct. By contributing to this project, you agree to abide by its terms.

## License

`gemini_self_protector` was created by lethanhphuc. It is licensed under the terms of the MIT license.

## Credits

`gemini_self_protector` was created with [`cookiecutter`](https://cookiecutter.readthedocs.io/en/latest/) and the `py-pkgs-cookiecutter` [template](https://github.com/py-pkgs/py-pkgs-cookiecutter).
