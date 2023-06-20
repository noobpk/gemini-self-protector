from flask import request, make_response
from ._config import _Config
from ._utils import _Utils
from ._logger import logger
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
import json
import ast


class _Protect(object):

    def __secure_response_header__(response):
        try:
            server_name = _Config.get_tb_config().server_name
            global_protect_mode = _Config.get_tb_config().global_protect_mode
            http_method_allow = _Config.get_tb_config().http_method_allow
            cors = _Config.get_tb_config().cors
            cors_origin = cors['origin']
            cors_method = cors['methods']
            cors_credential = cors['credentials']
            cors_header = cors['headers']
            http_method_list = ast.literal_eval(http_method_allow)

            response.headers['Server'] = server_name
            response.headers['X-Gemini-Self-Protector'] = global_protect_mode
            response.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
            response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
            response.headers['Expect-CT'] = 'enforce; max-age=31536000'
            response.headers['Feature-Policy'] = "fullscreen 'self'"
            response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
            response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1'
            response.headers['X-Gemini-HTTP-Allow'] = ', '.join(
                http_method_list)
            response.headers['Access-Control-Allow-Origin'] = cors_origin
            response.headers['Access-Control-Allow-Methods'] = cors_method
            response.headers['Access-Control-Allow-Credentials'] = cors_credential
            response.headers['Access-Control-Allow-Headers'] = ', '.join(
                cors_header)
            return response
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Protect.__secure_response_header__', e))

    def __secure_cookie__(app):
        try:
            app.config.update(
                SESSION_COOKIE_SECURE=True,
                SESSION_COOKIE_HTTPONLY=True,
                SESSION_COOKIE_SAMESITE='Lax',
            )
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Protect.__secure_cookie__', e))

    def __handle_normal_request__(_request) -> None:
        try:
            normal_request = _Config.get_tb_summary().normal_request
            _Config.update_tb_summary({'normal_request': normal_request+1})
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Protect.__handle_normal_request__', e))

    def __handle_abnormal_request__(_request, _predict, _attack_type, _ticket) -> None:
        try:
            abnormal_request = _Config.get_tb_summary().abnormal_request
            _Config.update_tb_summary(
                {'abnormal_request': abnormal_request+1})
            _Config.store_tb_request_log(
                _ticket["IP"], _request, _attack_type, _predict, str(_ticket["EventID"]))
            logger.warning("[+] Gemini Alert: Abnormal detection - IP: {}. event ID: {}".format(
                _ticket["IP"], _ticket["EventID"]))
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Protect.__handle_abnormal_request__', e))

    def __handle_original_request__(_request, _full_request, _ticket) -> None:
        try:
            http_method_allow = _Config.get_tb_config().http_method_allow
            max_content_length = _Config.get_tb_config().max_content_length

            req_length = 0
            if 'Content-Length' in _request.headers:
                req_length = _request.headers["Content-Length"]

            if _request.method and _request.method in http_method_allow:
                if int(req_length) < max_content_length:
                    return True
                else:
                    _Protect.__handle_abnormal_request__(
                        _full_request, None, "Large Requests", _ticket)
                    return False
            else:
                _Protect.__handle_abnormal_request__(
                    _full_request, None, "HTTP Method Tampering", _ticket)
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Protect.__handle_original_request__', e))

    def __handle_abnormal_response__(_request_response, _predict, _attack_type, _ticket) -> None:
        try:
            abnormal_response = _Config.get_tb_summary().abnormal_response
            _Config.update_tb_summary(
                {'abnormal_response': abnormal_response+1})
            _Config.store_tb_request_log(
                _ticket["IP"], _request_response, _attack_type, _predict, str(_ticket["EventID"]))
            logger.warning("[+] Gemini Alert: Abnormal detection - IP: {}. event ID: {}".format(
                _ticket["IP"], _ticket["EventID"]))
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Protect.__handle_abnormal_response__', e))

    def __handle_original_response__(_request_response, _response, _ticket) -> None:
        try:
            def is_safe_url(target):
                trust_domain = _Config.get_tb_config().trust_domain
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
                        _Protect.__handle_abnormal_response__(
                            _request_response, None, "Unvalidated Redirects", _ticket)
                        return False
                    else:
                        return True
            else:
                return True
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Protect.__handle_original_response__', e))

    def __protect_flask_request__(gemini_protect_mode) -> None:
        try:
            sensitive_value = _Config.get_tb_config().sensitive_value
            req_method = request.method
            req_full_path = request.full_path
            req_headers = ''  # str(request.headers)
            req_body = None
            
            if request.data:
                req_body = request.data.decode('utf-8')
            elif request.values:
                data = request.values.to_dict()
                req_body = json.dumps(data)

            _full_request = '{} {}\n{}\n{}'.format(
                req_method, req_full_path, req_headers, req_body)

            _ticket = _Utils.insident_ticket()

            if gemini_protect_mode in ('monitor', 'block'):
                if _Protect.__handle_original_request__(request, _full_request, _ticket):
                    payload = _Utils.decoder(_full_request)

                    predict = _Utils.web_vuln_detect_predict(payload)

                    if predict < sensitive_value:
                        status = True
                        _Protect.__handle_normal_request__(_full_request)
                    else:
                        _Protect.__handle_abnormal_request__(_full_request, predict, "Malicious Request", _ticket)
                        if gemini_protect_mode == 'monitor':
                            status = True
                        else:
                            status = False
                else:
                    if gemini_protect_mode == 'monitor':
                        status = True
                    else:
                        status = False

                return {"Status": status, "Ticket": _ticket}
            else:
                logger.error("[x_x] Invalid Protect Mode. Protect mode must be: monitor - block - off")
                status = True
                return {"Status": status}

        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {}".format(e))

    def __protect_flask_response__(safe_redirect, original_response, gemini_protect_mode) -> None:
        try:
            if int(safe_redirect):
                req_method = request.method
                req_full_path = request.full_path
                req_headers = ''  # request.headers
                req_body = None
                
                if request.data:
                    req_body = request.data.decode('utf-8')
                elif request.values:
                    data = request.values.to_dict()
                    req_body = json.dumps(data)

                res_status = original_response.status
                res_headers = original_response.headers
                res_data = original_response.data

                _full_response = '{}\n{}'.format(res_status, res_headers)
                _full_request_response = '{} {}\n{}\n{}\n----\n{}'.format(
                    req_method, req_full_path, req_headers, req_body, _full_response)

                _ticket = _Utils.insident_ticket()

                if gemini_protect_mode in ('monitor', 'block'):
                    if _Protect.__handle_original_response__(_full_request_response, original_response, _ticket):
                        status = True
                    else:
                        if gemini_protect_mode == 'monitor':
                            status = True
                        else:
                            status = False

                    return {"Status": status, "Ticket": _ticket}
                else:
                    logger.error("[x_x] Invalid Protect Mode. Protect mode must be: monitor - block - off")
                    status = True
                    return {"Status": status}
            else:
                status = True
                return {"Status": status}

        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {}".format(e))
