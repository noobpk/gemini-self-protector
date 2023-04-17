from flask import request, make_response
from ._config import _Config
from ._utils import _Utils
from ._logger import logger
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
import json

class _Protect(object):

    def __secure_response_header__(response):
        try:
            global_protect_mode = _Config.get_config('gemini_global_protect_mode')
            http_method_allow = _Config.get_config('gemini_http_method_allow')

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
            response.headers['X-Gemini-HTTP-Allow'] = ', '.join(http_method_allow)
            return response
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def __handle_normal_request__(_request, predict, _ticket) -> None:
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

    def __handle_abnormal_request__(_request, _predict, _attack_type, _ticket) -> None:
        """
        This function is used to handle abnormal requests

        :param _request: The request that was sent to the server
        :param _predict: The prediction of the model
        :param _attack_type: The type of attack that was detected
        """
        try:
            abnormal_request = _Config.get_config('gemini_abnormal_request')
            _Config.update_config({'gemini_abnormal_request': abnormal_request+1})
            now = datetime.now()
            current_time = now.strftime("%Y-%m-%d %H:%M:%S")
            _dict = {"Time": current_time, "Request": _request, "AttackType": _attack_type, "Predict": _predict, "IncidentID": str(_ticket["IncidentID"])}
            _Config.update_data_store(_dict)
            logger.warning("[+] Gemini Alert: Abnormal detection - IP: {}. Incident ID: {}".format(_ticket["IP"], _ticket["IncidentID"]))
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def __handle_original_request__(_request, _full_request, _ticket) -> None:
        try:
            http_method_allow = _Config.get_config('gemini_http_method_allow')
            max_content_length = _Config.get_config('gemini_max_content_length')

            req_length = 0
            if 'Content-Length' in _request.headers:
                req_length = _request.headers["Content-Length"]

            if _request.method and _request.method in http_method_allow:
                if int(req_length) < max_content_length:
                    return True
                else:
                    _Protect.__handle_abnormal_request__(_full_request, None, "Large Requests", _ticket)
                    return False
            else:
                _Protect.__handle_abnormal_request__(_full_request, None, "HTTP Method Tampering", _ticket)
                return False
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def __handle_abnormal_response__(_request_response, _predict, _attack_type, _ticket) -> None:
        try:
            now = datetime.now()
            current_time = now.strftime("%Y-%m-%d %H:%M:%S")
            _dict = {"Time": current_time, "Request": _request_response, "AttackType": _attack_type, "Predict": _predict, "IncidentID": str(_ticket["IncidentID"])}
            _Config.update_data_store(_dict)
            logger.warning("[+] Gemini Alert: Abnormal detection - IP: {}. Incident ID: {}".format(_ticket["IP"], _ticket["IncidentID"]))
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def __handle_original_response__(_request_response, _response, _ticket) -> None:
        try:
            def is_safe_url(target):
                trust_domain = _Config.get_config('gemini_trust_domain')
                ref_url = urlparse(request.host_url)
                test_url = urlparse(urljoin(request.host_url, target))
                return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc or test_url.netloc in trust_domain

            if _response.status_code == 302 and 'Location' in _response.headers:
                external_url = _response.headers['Location']
                # get the base URL of the request
                base_url = request.base_url
                # check if the external URL is on a different domain
                if urlparse(external_url).netloc != urlparse(base_url).netloc:
                    # check if the external URL is safe to redirect to
                    if not is_safe_url(external_url):
                        _Protect.__handle_abnormal_response__(_request_response, None, "Unvalidated Redirects", _ticket)
                        return False
                    else:
                        return True
            else:
                return True
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def __protect_flask_request__(gemini_protect_mode) -> None:
        try:
            # It's getting the sensitive value from the config.yml file.
            sensitive_value = _Config.get_config('gemini_sensitive_value')
            # It's getting the request method, request full path, request headers, and request
            # data. Then it's formatting the request method, request full path, request headers,
            # and request data into a string.
            req_method = request.method
            req_full_path = request.full_path
            req_headers = ''#str(request.headers)
            req_body = None
            if request.data:
                req_body = request.data.decode('utf-8')
            elif request.values:
                data = request.values.to_dict()
                req_body = json.dumps(data)
            else:
                req_body = None

            _full_request = '{} {}\n{}\n{}'.format(req_method, req_full_path, req_headers, req_body)

            _ticket = _Utils.insident_ticket()
            if gemini_protect_mode == 'monitor':
                if _Protect.__handle_original_request__(request, _full_request, _ticket):
                    # It's decoding the request body.
                    payload = _Utils.decoder(_full_request)
                    # It's using the payload to predict if it's a web vulnerability or not.
                    predict = _Utils.web_vuln_detect_predict(payload)
                    if predict < sensitive_value:
                        status = True
                        _Protect.__handle_normal_request__(_full_request, predict, _ticket)
                        return {"Status": status, "Ticket": _ticket}
                    else:
                        status = True
                        _Protect.__handle_abnormal_request__(_full_request, predict, "Malicious Request")
                        return {"Status": status, "Ticket": _ticket}
                else:
                    status = True
                    return {"Status": status, "Ticket": _ticket}
            elif gemini_protect_mode == 'block':
                if _Protect.__handle_original_request__(request, _full_request, _ticket):
                    # It's decoding the request body.
                    payload = _Utils.decoder(_full_request)
                    # It's using the payload to predict if it's a web vulnerability or not.
                    predict = _Utils.web_vuln_detect_predict(payload)

                    # It's checking if the predict value is less than the sensitive value. If it is, then it
                    # will return a status of True (safe). If it's not, then it will return a status of False (unsafe).
                    if predict < sensitive_value:
                        status = True
                        _Protect.__handle_normal_request__(_full_request, predict, _ticket)
                        return {"Status": status, "Ticket": _ticket}
                    else:
                        status = False
                        _Protect.__handle_abnormal_request__(_full_request, predict, "Malicious Request", _ticket)
                        return {"Status": status, "Ticket": _ticket}
                else:
                    status = False
                    return {"Status": status, "Ticket": _ticket}
            elif gemini_protect_mode == 'off':
                logger.info("[+] Gemini-Self-Protector is Off")
                status = True
                return {"Status": status}
            else:
                logger.error(
                    "[x_x] Invalid Protect Mode. Protect mode must be: monitor - block - off")
                status = True
                return {"Status": status}
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def __protect_flask_response__(safe_redirect, original_response, gemini_protect_mode) -> None:
        try:
            if safe_redirect == 'on':
                req_method = request.method
                req_full_path = request.full_path
                req_headers = ''#request.headers
                req_body = None
                if request.data:
                    req_body = request.data.decode('utf-8')
                elif request.values:
                    data = request.values.to_dict()
                    req_body = json.dumps(data)
                else:
                    req_body = None

                res_status = original_response.status
                res_headers = original_response.headers
                res_data = original_response.data

                _full_response = '{}\n{}'.format(res_status, res_headers)
                _full_request_response = '{} {}\n{}\n{}\n----\n{}'.format(req_method, req_full_path, req_headers, req_body, _full_response)

                _ticket = _Utils.insident_ticket()
                if gemini_protect_mode == 'monitor':
                    if _Protect.__handle_original_response__(_full_request_response, original_response, _ticket):
                        status = True
                        return {"Status": status, "Ticket": _ticket}
                    else:
                        status = True
                        return {"Status": status, "Ticket": _ticket}
                elif gemini_protect_mode == 'block':
                    if _Protect.__handle_original_response__(_full_request_response, original_response, _ticket):
                        status = True
                        return {"Status": status, "Ticket": _ticket}
                    else:
                        status = False
                        return {"Status": status, "Ticket": _ticket}
                elif gemini_protect_mode == 'off':
                    logger.info("[+] Gemini-Self-Protector is Off")
                    status = True
                    return {"Status": status}
                else:
                    logger.error(
                        "[x_x] Invalid Protect Mode. Protect mode must be: monitor - block - off")
                    status = True
                    return {"Status": status}
            else:
                logger.info("[+] Gemini-Self-Protector Safe Redirect is Off")
                status = True
                return {"Status": status}
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
