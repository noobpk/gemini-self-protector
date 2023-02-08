from ._gemini import _Gemini
from functools import wraps
from flask import Flask, request, make_response

class GeminiManager(object):

    def __init__(self, flask_app: Flask = None, license_key="w", protect_mode="w", sensitive_value="w"):
        """
        The function takes in a license key and a protect mode, and then verifies the license key and
        protect mode
        
        :param license_key: This is the license key that you will be using to protect your code
        :param protect_mode: This is the global protect mode. It can be either 'on' or 'off'
        :param sensitive_value: This is the value that you want to protect
        """
        self.license_key = license_key
        self.verify_license_key = _Gemini.verify_license_key(self.license_key)
        self.global_protect_mode = _Gemini.verify_protect_mode(protect_mode)
        self.sensitive_value = _Gemini.verify_sensitive(sensitive_value)
        # Register this extension with the flask app now (if it is provided)
        if flask_app is not None:
            self.init_flask_app(flask_app)

    def init_flask_app(self, flask_app: Flask) -> None:
        pass

    def flask_protect_extended(self, protect_mode=None):
        """
        This function is used to protect the Flask application from malicious requests
        
        :param protect_mode: This is the mode you want to use for the protection
        :return: The function is being returned.
        """
        def _gemini_self_protect(f):
            @wraps(f)
            def __gemini_self_protect(*args, **kwargs):
                if protect_mode is None:
                    gemini_protect_mode = self.global_protect_mode
                elif protect_mode is not None and self.global_protect_mode == 'off':
                    gemini_protect_mode = 'off'
                else:
                    gemini_protect_mode = protect_mode

                protect = _Gemini.__load_protect_flask__(gemini_protect_mode, self.sensitive_value)
                if protect[0]:
                    response = make_response(f(*args, **kwargs))
                    response.headers['X-Gemini-Self-Protector'] = gemini_protect_mode
                    return response
                else:
                    current_time = protect[1]
                    ip_address = protect[2]
                    incedent_id = protect[3]
                    response = make_response("This request was blocked by Gemini \n The Runtime Application Self-Protection Solution \n\n Time: {} \n Your IP : {} \n\n Incident ID: {}".format(current_time, ip_address, incedent_id), 200)
                    response.headers['X-Gemini-Self-Protector'] = gemini_protect_mode
                    return response
            return __gemini_self_protect
        return _gemini_self_protect

    def django_protect_extended(self):
        return True
