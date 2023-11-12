import os
from ._gemini import _Gemini
from ._gui import _Gemini_GUI
from ._cli import _Gemini_CLI
from ._behavior import _Behavior
from functools import wraps
from flask import Flask, make_response
from ._logger import logger
from datetime import datetime, timezone
from cachetools import TTLCache
import time

cache = TTLCache(maxsize=1000, ttl=60)  # Max size of 1000 and TTL of 60 seconds


class GeminiManager(object):
    def __init__(self, flask_app: Flask = None):
        _Gemini.get_gemini_banner()

        # This is creating a directory called gemini-protector in the current working directory.
        running_directory = os.getcwd()
        gemini_working_directory = os.path.join(running_directory, r"gemini-protector")
        self.path = gemini_working_directory
        if not os.path.exists(gemini_working_directory):
            os.makedirs(gemini_working_directory)

        if not os.path.isfile(gemini_working_directory + "/gemini.db"):
            _Gemini.init_gemini_database(gemini_working_directory)

        if flask_app is not None:
            _Gemini_GUI(flask_app)
        else:
            _Gemini_CLI()

    def flask_protect_extended(self, protect_mode=None) -> None:
        def _gemini_self_protect(f):
            @wraps(f)
            def __gemini_self_protect(*args, **kwargs):
                start_time = time.time()

                _Gemini.calulate_total_access()
                is_install = _Gemini.get_gemini_config().is_install
                _ip_address = _Gemini.get_flask_client_ip()
                is_enable_anti_dos = _Gemini.get_gemini_config().anti_dos
                is_enable_acl = _Gemini.get_gemini_config().enable_acl
                is_protect_response = _Gemini.get_gemini_config().protect_response
                mrpm = _Gemini.get_gemini_config().max_requests_per_minute

                # This code block checks if the `is_install` variable is equal to 0. If it is, it
                # means that the Gemini self-protector is not installed or set up properly. In this
                # case, it creates a response with a message asking the user to set up the Gemini
                # self-protector and returns the response.
                if int(is_install) == 0:
                    response = make_response(
                        "<h5>Please setup gemini-self-protector.</h5>"
                    )
                    return response

                # This code block is responsible for implementing anti-DDoS (Distributed Denial of
                # Service) protection in the GeminiManager class.
                if int(is_enable_anti_dos):
                    request_key = (
                        f"{_ip_address}_{datetime.now().strftime('%Y-%m-%d %H:%M')}"
                    )

                    request_count = cache.get(request_key)

                    if request_count is None:
                        cache[request_key] = 1
                    elif request_count >= mrpm:
                        anti_dos = _Gemini.__load_mini_anti_dos__()
                        response = make_response(
                            "<h5>This request was blocked by Gemini</h5><h5>The Runtime Application Self-Protection Solution</h5><h5>Time: {} </h5><h5>Your IP : {} </h5><h5>Event ID: {} </h5>".format(
                                anti_dos["Time"], anti_dos["IP"], anti_dos["EventID"]
                            ),
                            200,
                        )
                        logger.warning(
                            "[+] Gemini Alert: DDOS detection - IP: {}. Event ID: {}".format(
                                anti_dos["IP"], anti_dos["EventID"]
                            )
                        )
                        if not int(is_protect_response):
                            return response

                        response = _Gemini.make_secure_response_header(response)
                        return response

                    else:
                        cache[request_key] += 1

                # This code block is responsible for implementing Access Control List (ACL) blocking
                # in the GeminiManager class.
                if int(is_enable_acl) and _Gemini.check_gemini_acl(_ip_address):
                    _ticket = _Gemini.generate_insident_ticket()
                    abnormal_request = _Gemini.get_gemini_summary().abnormal_request
                    _Gemini.update_gemini_summary(
                        {"abnormal_request": abnormal_request + 1}
                    )
                    _Gemini.store_gemini_request_log(
                        ipaddress=_ticket["IP"],
                        request=None,
                        attack_type="ACL Block",
                        predict=None,
                        event_id=str(_ticket["EventID"]),
                    )
                    response = make_response(
                        "<h5>This request was blocked by Gemini</h5><h5>The Runtime Application Self-Protection Solution</h5><h5>Time: {} </h5><h5>Your IP : {} </h5><h5>Event ID: {} </h5>".format(
                            _ticket["Time"], _ticket["IP"], _ticket["EventID"]
                        ),
                        200,
                    )
                    logger.warning(
                        "[+] Gemini Alert: ACL Block - IP: {}. Event ID: {}".format(
                            _ticket["IP"], _ticket["EventID"]
                        )
                    )
                    if not int(is_protect_response):
                        return response

                    response = _Gemini.make_secure_response_header(response)
                    return response

                global_protect_mode = _Gemini.get_gemini_config().global_protect_mode

                # This code block checks if the `global_protect_mode` variable is set to "off". If it
                # is, it means that the Gemini self-protector is turned off and should not apply any
                # protection measures. In this case, it directly calls the original function `f(*args,
                # **kwargs)` and returns the response without any modifications or additional
                # protection.
                if global_protect_mode == "off":
                    response = make_response(f(*args, **kwargs))
                    return response

                # The line `behavior_id = _Behavior.init_behavior()` is initializing a new behavior in
                # the Gemini self-protector. The `_Behavior` class is responsible for managing and
                # tracking the behavior of requests in the Gemini self-protector. The
                # `init_behavior()` method creates a new behavior entry in the Gemini database and
                # returns the behavior ID. This behavior ID is then used to track and update the
                # behavior of the current request.
                behavior_id = _Behavior.init_behavior()

                current_protect_mode = (
                    protect_mode if protect_mode is not None else global_protect_mode
                )
                gemini_protect_mode = current_protect_mode

                logger.info(
                    "[+] This request is currently being executed with the protective {0} mode.".format(
                        "monitoring"
                        if gemini_protect_mode == "monitor"
                        else "protecting"
                    )
                )

                # The line `protect_request =
                # _Gemini.__load_protect_flask_request__(gemini_protect_mode, behavior_id)` is calling
                # the `__load_protect_flask_request__` method from the `_Gemini` class. This method is
                # responsible for loading and processing the request data for protection in the Gemini
                # self-protector. It takes two arguments: `gemini_protect_mode` and `behavior_id`.
                protect_request = _Gemini.__load_protect_flask_request__(
                    gemini_protect_mode, behavior_id
                )

                # The above code is a snippet of Python code. It appears to be a part of a larger
                # codebase that includes a framework called Gemini, which is a Runtime Application
                # Self-Protection (RASP) solution.
                if protect_request["Status"]:
                    response = make_response(f(*args, **kwargs))

                    if not int(is_protect_response):
                        end_time = time.time()
                        elapsed_time = end_time - start_time
                        _Gemini.update_gemini_behavior_log(
                            behavior_id,
                            response.status_code,
                            start_time,
                            end_time,
                            elapsed_time,
                        )
                        return response

                    protect_response = _Gemini.__load_protect_flask_response__(
                        response, gemini_protect_mode, behavior_id
                    )

                    if protect_response["Status"] and int(is_protect_response):
                        response = _Gemini.make_secure_response_header(response)
                    else:
                        current_time = protect_response["Ticket"]["Time"]
                        ip_address = protect_response["Ticket"]["IP"]
                        incedent_id = protect_response["Ticket"]["EventID"]
                        response = make_response(
                            "<h5>This request was blocked by Gemini</h5><h5>The Runtime Application Self-Protection Solution</h5><h5>Time: {} </h5><h5>Your IP : {} </h5><h5>Event ID: {} </h5>".format(
                                current_time, ip_address, incedent_id
                            ),
                            200,
                        )
                        response = _Gemini.make_secure_response_header(response)
                else:
                    current_time = protect_request["Ticket"]["Time"]
                    ip_address = protect_request["Ticket"]["IP"]
                    incedent_id = protect_request["Ticket"]["EventID"]
                    response = make_response(
                        "<h5>This request was blocked by Gemini</h5><h5>The Runtime Application Self-Protection Solution</h5><h5>Time: {} </h5><h5>Your IP : {} </h5><h5>Event ID: {} </h5>".format(
                            current_time, ip_address, incedent_id
                        ),
                        200,
                    )

                    if not int(is_protect_response):
                        end_time = time.time()
                        elapsed_time = end_time - start_time
                        _Gemini.update_gemini_behavior_log(
                            behavior_id,
                            response.status_code,
                            start_time,
                            end_time,
                            elapsed_time,
                        )
                        return response

                    response = _Gemini.make_secure_response_header(response)

                end_time = time.time()
                elapsed_time = end_time - start_time
                _Gemini.update_gemini_behavior_log(
                    behavior_id,
                    response.status_code,
                    start_time,
                    end_time,
                    elapsed_time,
                )
                return response

            return __gemini_self_protect

        return _gemini_self_protect

    def django_protect_extended(self):
        return True
