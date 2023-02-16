from flask import request
from ._config import _Config
from ._utils import _Utils
from ._logger import logger
from datetime import datetime, timezone

class _Protect(object):

    def __handle_response_headers__(response):
        try:
            global_protect_mode = _Config.get_config('gemini_global_protect_mode')
            response.headers['X-Gemini-Self-Protector'] = global_protect_mode
            response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
            response.headers['Expect-CT'] = 'enforce; max-age=31536000'
            response.headers['Feature-Policy'] = "fullscreen 'self'"
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1'
            return response
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def __handle_normal_request__(_request, predict = None):
        """
        This function is used to handle normal requests

        :param _request: The request that was sent to the server
        :param predict: This is the prediction of the model
        """
        try:
            normal_request = _Config.get_config('gemini_normal_request')
            _Config.update_config({'gemini_normal_request': normal_request+1})
            # now = datetime.now()
            # current_time = now.strftime("%Y-%m-%d %H:%M:%S")
            # _dict = {"Time": current_time, "Request": _request, "Predict": predict}
            # _Config.update_data_store(_dict)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def __handle_abnormal_request__(_request, predict = None):
        """
        This function is used to handle abnormal requests

        :param _request: The request that was sent to the server
        :param predict: The prediction of the model
        """
        try:
            abnormal_request = _Config.get_config('gemini_abnormal_request')
            _Config.update_config({'gemini_abnormal_request': abnormal_request+1})
            now = datetime.now()
            current_time = now.strftime("%Y-%m-%d %H:%M:%S")
            _dict = {"Time": current_time, "Request": _request, "Predict": predict}
            _Config.update_data_store(_dict)
            _ticket = _Utils.insident_ticket()
            logger.warning("[+] Gemini Alert: Abnormal detection - IP: {}. Incident ID: {}".format(_ticket[1], _ticket[2]))
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def __handle_large_request__(req_length):
        """
        If the request is less than the max content length, return true, else return false
        :return: a boolean value.
        """
        try:
            max_content_length = _Config.get_config('gemini_max_content_length')
            if req_length:
                if int(req_length) < max_content_length:
                    return True
                else:
                    return False
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def __protect_flask__(gemini_protect_mode):
        try:
            if gemini_protect_mode == 'monitor':
                # It's getting the sensitive value from the config.yml file.
                sensitive_value = _Config.get_config('gemini_sensitive_value')
                # It's getting the request method, request full path, request headers, and request
                # data. Then it's formatting the request method, request full path, request headers,
                # and request data into a string.
                req_method = request.method
                req_full_path = request.full_path
                req_headers = request.headers
                req_data = request.data
                req_length = None
                if 'Content-Length' in req_headers:
                    req_length = request.headers["Content-Length"]
                _request = '{} {}\n{}\n{}'.format(req_method, req_full_path, req_headers, req_data.decode("utf-8"))

                _ticket = _Utils.insident_ticket()
                if _Protect.__handle_large_request__(req_length):
                    # It's decoding the request body.
                    payload = _Utils.decoder(_request)
                    # It's using the payload to predict if it's a web vulnerability or not.
                    predict = _Utils.web_vuln_detect_predict(payload)
                    if predict < sensitive_value:
                        status = True
                        _Protect.__handle_normal_request__(_request, predict)
                        return [status, _ticket]
                    else:
                        status = True
                        _Protect.__handle_abnormal_request__(_request, predict)
                        return [status, _ticket]
                else:
                    status = True
                    _Protect.__handle_abnormal_request__(_request)
                    return [status, _ticket]
            elif gemini_protect_mode == 'block':
                # It's getting the sensitive value from the config.yml file.
                sensitive_value = _Config.get_config('gemini_sensitive_value')
                # It's getting the request method, request full path, request headers, and request
                # data. Then it's formatting the request method, request full path, request headers,
                # and request data into a string.
                req_method = request.method
                req_full_path = request.full_path
                req_headers = request.headers
                req_data = request.data
                req_length = None
                if 'Content-Length' in req_headers:
                    req_length = request.headers["Content-Length"]
                _request = '{} {}\n{}\n{}'.format(req_method, req_full_path, req_headers, req_data.decode("utf-8"))

                _ticket = _Utils.insident_ticket()

                if _Protect.__handle_large_request__(req_length):
                    # It's decoding the request body.
                    payload = _Utils.decoder(_request)
                    # It's using the payload to predict if it's a web vulnerability or not.
                    predict = _Utils.web_vuln_detect_predict(payload)

                    _ticket = _Utils.insident_ticket()
                    # It's checking if the predict value is less than the sensitive value. If it is, then it
                    # will return a status of True (safe). If it's not, then it will return a status of False (unsafe).
                    if predict < sensitive_value:
                        status = True
                        _Protect.__handle_normal_request__(_request, predict)
                        return [status, _ticket]
                    else:
                        status = False
                        _Protect.__handle_abnormal_request__(_request, predict)
                        return [status, _ticket]
                else:
                    status = False
                    _Protect.__handle_abnormal_request__(_request)
                    return [status, _ticket]
            elif gemini_protect_mode == 'off':
                logger.info("[+] Gemini-Self-Protector is Off")
                pass
            else:
                logger.error(
                    "[x_x] Invalid Protect Mode. Protect mode must be: monitor - block - off")
                pass
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
