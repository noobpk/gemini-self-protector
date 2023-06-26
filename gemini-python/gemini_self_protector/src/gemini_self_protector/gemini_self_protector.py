import os
from ._gemini import _Gemini
from ._gui import _Gemini_GUI
from ._cli import _Gemini_CLI
from functools import wraps
from flask import Flask, make_response
from ._logger import logger
from datetime import datetime, timezone
from cachetools import TTLCache

cache = TTLCache(maxsize=1000, ttl=60)  # Max size of 1000 and TTL of 60 seconds

class GeminiManager(object):

    def __init__(self, flask_app: Flask = None):
        _Gemini.get_gemini_banner()

        # This is creating a directory called gemini-protector in the current working directory.
        running_directory = os.getcwd()
        gemini_working_directory = os.path.join(
            running_directory, r'gemini-protector')
        self.path = gemini_working_directory
        if not os.path.exists(gemini_working_directory):
            os.makedirs(gemini_working_directory)

        if not os.path.isfile(gemini_working_directory+'/gemini.db'):
            _Gemini.init_gemini_database(gemini_working_directory)

        if flask_app is not None:
            _Gemini_GUI(flask_app)
        else:
            _Gemini_CLI()

    def flask_protect_extended(self, protect_mode=None) -> None:
        def _gemini_self_protect(f):
            @wraps(f)
            def __gemini_self_protect(*args, **kwargs):
                _Gemini.calulate_total_access()
                _ip_address = _Gemini.get_flask_client_ip()
                is_enable_anti_dos = _Gemini.get_gemini_config().anti_dos
                is_enable_acl = _Gemini.get_gemini_config().enable_acl
                is_protect_response = _Gemini.get_gemini_config().protect_response
                mrpm = _Gemini.get_gemini_config().max_requests_per_minute

                if int(is_enable_anti_dos):
                    request_key = f"{_ip_address}_{datetime.now().strftime('%Y-%m-%d %H:%M')}"

                    request_count = cache.get(request_key)
                    if request_count is None:
                        cache[request_key] = 1
                    elif request_count >= mrpm:
                        anti_dos = _Gemini.__load_mini_anti_dos__()
                        response = make_response("Your IP Address was blocked by Gemini \n The Runtime Application Self-Protection Solution \n\n Time: {} \n Your IP : {} \n\n Event ID: {}".format(
                            anti_dos["Time"], anti_dos["IP"], anti_dos["EventID"]), 200)
                        if not int(is_protect_response):
                            return response
                    
                        response = _Gemini.make_secure_response_header(response)
                        return response
                    
                    else:
                        cache[request_key] += 1

                if int(is_enable_acl) and _Gemini.check_gemini_acl(_ip_address):
                    _ticket = _Gemini.generate_insident_ticket()
                    abnormal_request = _Gemini.get_gemini_summary().abnormal_request
                    _Gemini.update_gemini_summary(
                        {'abnormal_request': abnormal_request+1})
                    _Gemini.store_gemini_request_log(ipaddress=_ticket["IP"], request=None, attack_type="ACL Block", predict=None, event_id=str(_ticket["EventID"]))
                    response = make_response("Your IP Address was blocked by Gemini \n The Runtime Application Self-Protection Solution \n\n Time: {} \n Your IP : {} \n\n Event ID: {}".format(
                        _ticket["Time"], _ticket["IP"], _ticket["EventID"]), 200)
                        
                    if not int(is_protect_response):
                        return response
                    
                    response = _Gemini.make_secure_response_header(response)
                    return response

                global_protect_mode = _Gemini.get_gemini_config().global_protect_mode

                if global_protect_mode == 'off':
                    response = make_response(f(*args, **kwargs))
                    return response

                current_protect_mode = protect_mode if protect_mode is not None else global_protect_mode
                gemini_protect_mode = current_protect_mode

                logger.info("[+] This request is currently being executed with the protective {0} mode.".format(
                    'monitoring' if gemini_protect_mode == 'monitor' else 'blocking'))

                protect_request = _Gemini.__load_protect_flask_request__(gemini_protect_mode)

                if protect_request["Status"]:
                    response = make_response(f(*args, **kwargs))

                    if not int(is_protect_response):
                        return response

                    protect_response = _Gemini.__load_protect_flask_response__(response, gemini_protect_mode)

                    if protect_response["Status"] and int(is_protect_response):
                        response = _Gemini.make_secure_response_header(response)
                    else:
                        current_time = protect_response["Ticket"]["Time"]
                        ip_address = protect_response["Ticket"]["IP"]
                        incedent_id = protect_response["Ticket"]["EventID"]
                        response = make_response("This request was blocked by Gemini \n The Runtime Application Self-Protection Solution \n\n Time: {} \n Your IP : {} \n\n Event ID: {}".format(
                            current_time, ip_address, incedent_id), 200)
                        response = _Gemini.make_secure_response_header(response)
                else:
                    current_time = protect_request["Ticket"]["Time"]
                    ip_address = protect_request["Ticket"]["IP"]
                    incedent_id = protect_request["Ticket"]["EventID"]
                    response = make_response("This request was blocked by Gemini \n The Runtime Application Self-Protection Solution \n\n Time: {} \n Your IP : {} \n\n Event ID: {}".format(
                        current_time, ip_address, incedent_id), 200)
                    
                    if not int(is_protect_response):
                        return response

                    response = _Gemini.make_secure_response_header(response)

                return response

            return __gemini_self_protect

        return _gemini_self_protect

    def django_protect_extended(self):
        return True
