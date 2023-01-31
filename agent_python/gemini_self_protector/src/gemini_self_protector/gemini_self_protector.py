from ._gemini import _Gemini
from functools import wraps


class GeminiManager(object):

    def __init__(self, license_key, protect_mode):
        self.license_key = license_key
        self.verify_license_key = _Gemini.verify_license_key(self.license_key)
        self.global_protect_mode = _Gemini.verify_protect_mode(protect_mode)

    def flask_protect_extended(self, protect_mode=None):

        def _gemini_self_protect(f):
            @wraps(f)
            def __gemini_self_protect(*args, **kwargs):
                if protect_mode is None:
                    gemini_protect_mode = self.global_protect_mode
                elif protect_mode is not None and self.global_protect_mode == 'off':
                    gemini_protect_mode = 'off'
                else:
                    gemini_protect_mode = protect_mode

                protect = _Gemini.__load_protect__(gemini_protect_mode)

                if protect:
                    return f(*args, **kwargs)
                else:
                    return 'Malicious Request - SOS', 200
            return __gemini_self_protect
        return _gemini_self_protect

    def django_protect_extended(self):
        return True
