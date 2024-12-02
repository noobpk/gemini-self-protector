import os
import re
import base64
import html
import urllib.parse
import requests
import uuid
import binascii
from flask import request
from ._config import _Config
from ._logger import logger
from datetime import datetime, timezone
import socket
from hashlib import sha256
from requests.exceptions import ConnectionError
import psutil

class _Utils(object):
    def g_wvd_serve_predict(_payload) -> None:
        """
        It takes a payload as input and returns the accuracy of the prediction

        :param payload: The payload is the data that you want to send to the API. In this case, it's the
        data that you want to predict
        :return: The accuracy of the prediction.
        """
        try:
            g_wvd_serve = _Config.get_tb_config().g_wvd_serve
            g_serve_key = _Config.get_tb_config().g_serve_key
            headers = {"Content-Type": "application/json", "Authorization": g_serve_key}
            client_ip = _Utils.flask_client_ip()
            response = requests.post(
                f"{g_wvd_serve}/predict",
                json={"ip": client_ip, "data": _payload},
                headers=headers,
            )
            data = response.json()

            if response.status_code == 200 and "threat_metrix" in data:
                score = data["threat_metrix"]["score"]
                hash = data["threat_metrix"]["hash"]
                rbd_xss = data["threat_metrix"]["rbd_xss"]
                rbd_sqli = data["threat_metrix"]["rbd_sqli"]
                rbd_unknown = data["threat_metrix"]["rbd_unknown"]

                return {
                    "Status_code": 200,
                    "Score": score,
                    "Hash": hash,
                    "XSS": rbd_xss,
                    "SQLI": rbd_sqli,
                    "UNKNOWN": rbd_unknown,
                }
            else:
                logger.warning(
                    "[!] Cannot connect to predict server. Gemini-self protector cannot predict this request."
                )
                return {
                    "Status_code": 000,
                    "Score": 0,
                    "Hash": None,
                    "XSS": None,
                    "SQLI": None,
                    "UNKNOWN": None,
                }
        except ConnectionError:
            logger.error("[x_x] Connection refused - Cannot connect to G-WVD")
            return {
                "Status_code": 000,
                "Score": 0,
                "Hash": None,
                "XSS": None,
                "SQLI": None,
                "UNKNOWN": None,
            }
        except requests.exceptions.RequestException as e:
            logger.warning(
                "[!] Cannot connect to predict server. Gemini-self protector cannot predict this request."
            )
            return {
                "Status_code": 000,
                "Score": 0,
                "Hash": None,
                "XSS": None,
                "SQLI": None,
                "UNKNOWN": None,
            }
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Utils.g_wvd_serve_predict", e
                )
            )

    def flask_client_ip() -> None:
        """
        If the request has a header called X-Forwarded-For, return the first value in the list of values
        for that header. Otherwise, return the remote address
        :return: The IP address of the client.
        """
        try:
            if request.headers.getlist("X-Forwarded-For"):
                return request.headers.getlist("X-Forwarded-For")[0]
            else:
                return request.remote_addr
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Utils.flask_client_ip", e
                )
            )

    def socket_local_ip() -> None:
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            return local_ip
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Utils.socket_local_ip", e
                )
            )

    def generate_event_id() -> None:
        """
        This function generates a random UUID and returns it
        :return: A random UUID.
        """
        try:
            event_id = uuid.uuid4()
            return event_id
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Utils.generate_event_id", e
                )
            )

    def insident_ticket() -> None:
        try:
            time = datetime.now(timezone.utc)
            ip = _Utils.flask_client_ip()
            event_id = _Utils.generate_event_id()
            latitude = None
            longitude = None
            return {
                "Time": time,
                "IP": ip,
                "EventID": event_id,
                "Latitude": latitude,
                "Longitude": longitude,
            }
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Utils.insident_ticket", e
                )
            )

    def create_path() -> None:
        """
        It creates a random string of 20 characters and appends the string 'gemini' to it
        :return: A string
        """
        try:
            random = binascii.b2a_hex(os.urandom(20)).decode("utf-8")
            dashboard_path = str(random) + "/gemini"
            return dashboard_path
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Utils.create_path", e
                )
            )

    def load_banner():
        print(
            r"""\033[1;31m \n
             __   ___                    __   ___       ___     __   __   __  ___  ___  __  ___  __   __  
            / _` |__   |\/| | |\ | |    /__` |__  |    |__     |__) |__) /  \  |  |__  /  `  |  /  \ |__) 
            \__> |___  |  | | | \| |    .__/ |___ |___ |       |    |  \ \__/  |  |___ \__,  |  \__/ |  \ 
                                        https://noobpk.github.io          #noobboy
                Real-time Protect Your Application - The Runtime Application Self Protection (RASP) Solution
        """
        )
        print("")

    def g_wvd_serve_health(_self_context=None) -> None:
        try:
            g_wvd_serve = _Config.get_tb_config().g_wvd_serve
            g_serve_key = _Config.get_tb_config().g_serve_key

            if g_wvd_serve:
                client_ip = None
                if _self_context:
                    client_ip = _Utils.socket_local_ip()
                else:
                    client_ip = _Utils.flask_client_ip()
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": g_serve_key,
                }
                response = requests.post(
                    f"{g_wvd_serve}/predict",
                    json={"ip": client_ip, "data": "healthcheck"},
                    headers=headers,
                )
                data = response.json()

                if response and response.status_code == 200 and "threat_metrix" in data:
                    return True
                else:
                    return False
            return False
        except ConnectionError:
            logger.error("[x_x] Connection refused - Cannot connect to G-WVD")
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Validator.g_wvd_serve_health", e
                )
            )

    def g_serve_diagnostic() -> None:
        try:
            g_wvd_serve = _Config.get_tb_config().g_wvd_serve
            g_serve_key = _Config.get_tb_config().g_serve_key
            client_ip = _Utils.socket_local_ip()

            logger.info("[*] Try PingPong to G-WVD")
            ping_header = {"Authorization": g_serve_key}
            ping_response = requests.get(f"{g_wvd_serve}/ping", headers=ping_header)
            if ping_response.status_code == 200:
                logger.info("[G-WVD STATUS] 200 OK")
                logger.info("[*] Try predicting sample data")
                predict_header = {
                    "Content-Type": "application/json",
                    "Authorization": g_serve_key,
                }
                preidct_response = requests.post(
                    f"{g_wvd_serve}/predict",
                    json={"ip": client_ip, "data": "healthcheck"},
                    headers=predict_header,
                )
                if preidct_response.status_code == 200:
                    logger.info("[G-WVD STATUS] 200 OK")
                    return 200
                elif preidct_response.status_code == 401:
                    logger.warning("[G-WVD STATUS] UNAUTHORIZED")
                    return 401
                elif preidct_response.status_code == 500:
                    logger.error("[G-WVD STATUS] INTERNAL SERVER ERROR")
                    return 500
            elif ping_response.status_code == 401:
                logger.warning("[G-WVD STATUS] UNAUTHORIZED")
                return 401
            elif ping_response.status_code == 500:
                logger.error("[G-WVD STATUS] INTERNAL SERVER ERROR")
                return 500
        except ConnectionError:
            logger.error("[x_x] Connection refused - Cannot connect to G-WVD")
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Validator.diagnostic_predict_server", e
                )
            )

    def g_decoder_and_rule_based_detection(_string):
        try:
            rule_based_xss_found = False
            rule_based_sqli_found = False
            metrix = {
                "Score": None,
                "Hash": None,
                "XSS": None,
                "SQLI": None,
                "UNKNOWN": None,
            }

            """Decode a string using the specified encoding type."""

            # Remove the invalid escape sequences  - # Remove the backslash
            string = _string.replace(r"\%", "%").replace("\\", "").replace("<br/>", "")

            string = string.encode().decode("unicode_escape")

            string = urllib.parse.unquote(string)

            string = html.unescape(string)

            # Use a regular expression to find all base64-encoded segments in the string
            base64_pattern = r"( |,|;)base64,([A-Za-z0-9+/]*={0,2})"

            # Iterate over the matches and decode the base64-encoded data
            match = re.search(base64_pattern, string)
            if match:
                encoded_string = match.group(2)

                # Try first base64-decode
                try:
                    decoded_string = base64.b64decode(encoded_string).decode()
                    string = string.replace(encoded_string, decoded_string)
                except:
                    pass

                # Try second base64-decode
                try:
                    string = (
                        string.replace(r"\%", "%")
                        .replace("\\", "")
                        .replace("<br/>", "")
                        .replace(" ", "")
                    )
                    match = re.search(base64_pattern, string)

                    if match:
                        encoded_string = match.group(2)
                        try:
                            decoded_string = base64.b64decode(encoded_string).decode()
                            string = string.replace(encoded_string, decoded_string)
                        except:
                            pass
                except:
                    pass

            # Use this pattern for detect cross-site scripting
            xss_patterns = [
                r"(?:https?://|//)[^\s/]+\.js"
                r"((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)",
                r"((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)",
                r"((\%3C)|<)[^\n]+((\%3E)|>)",
            ]

            for pattern in xss_patterns:
                matches = re.findall(pattern, string, re.IGNORECASE | re.VERBOSE)
                if matches:
                    for match in matches:
                        # string = string.replace(match[0], '5dc6f09bb9f90381814ff9fcbfe0a685')
                        rule_based_xss_found = True
                        break

            # Lowercase string
            string = string.lower()

            # Use this pattern for detect sql injection
            sql_patterns = [
                r"(?:select\s+.+\s+from\s+.+)",
                r"(?:insert\s+.+\s+into\s+.+)",
                r"(?:update\s+.+\s+set\s+.+)",
                r"(?:delete\s+.+\s+from\s+.+)",
                r"(?:drop\s+.+)",
                r"(?:truncate\s+.+)",
                r"(?:alter\s+.+)",
                r"(?:exec\s+.+)",
                r"(\s*(all|any|not|and|between|in|like|or|some|contains|containsall|containskey)\s+.+[\=\>\<=\!\~]+.+)",
                r"(?:let\s+.+[\=]\s+.*)",
                r"(?:begin\s*.+\s*end)",
                r"(?:\s*[\/\*]+\s*.+\s*[\*\/]+)",
                r"(?:\s*(\-\-)\s*.+\s+)",
                r"(?:\s*(contains|containsall|containskey)\s+.+)",
                r"\w*((\%27)|('))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
                r"exec(\s|\+)+(s|x)p\w+",
            ]

            for pattern in sql_patterns:
                matches = re.findall(pattern, string, re.IGNORECASE | re.VERBOSE)
                if matches:
                    for match in matches:
                        # select * from noobpk; - 90e87fc8ba835e0d2bfeec5e3799ecfe
                        # string = string.replace(
                        #     match[0], ' 90e87fc8ba835e0d2bfeec5e3799ecfe')
                        rule_based_sqli_found = True
                        break

            string = string.encode("utf-8")
            # Calculate metrix
            if rule_based_xss_found or rule_based_sqli_found:
                metrix["Score"] = 99
                metrix["UNKNOWN"] = False
            else:
                metrix["Score"] = 0
                metrix["UNKNOWN"] = True

            metrix["Hash"] = sha256(string).hexdigest()
            metrix["XSS"] = rule_based_xss_found
            metrix["SQLI"] = rule_based_sqli_found
            return metrix
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Utils.g_rule_base_detection", e
                )
            )

    def g_server_performance():
        try:
            # Conversion factor for bytes to GB
            BYTES_TO_GB = 1_073_741_824

            server_metrix = {
                "CPU": None,
                "MEMORY": None,
                "NETWORK_IN": None,
                "NETWORK_OUT": None,
                "DISK_READ": None,
                "DISK_WRITE": None,
            }

            # Fetch CPU and memory metrics
            server_metrix["CPU"] = psutil.cpu_percent(interval=1)
            server_metrix["MEMORY"] = psutil.virtual_memory().percent

            # Fetch network metrics
            net_io = psutil.net_io_counters()
            server_metrix["NETWORK_IN"] = net_io.bytes_recv / BYTES_TO_GB  # Total bytes received
            server_metrix["NETWORK_OUT"] = net_io.bytes_sent / BYTES_TO_GB # Total bytes sent

            # Fetch disk metrics
            disk_io = psutil.disk_io_counters()
            server_metrix["DISK_READ"] = disk_io.read_bytes / BYTES_TO_GB  # Total bytes read
            server_metrix["DISK_WRITE"] = disk_io.write_bytes / BYTES_TO_GB  # Total bytes written

            # Round all values to 2 decimal places
            for key in server_metrix:
                if isinstance(server_metrix[key], (float, int)):
                    server_metrix[key] = round(server_metrix[key], 2)

            return server_metrix
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Utils.g_server_performance", e
                )
            )

class _Validator(object):
    def validate_g_serve_key(_key) -> None:
        try:
            if _key:
                g_wvd_serve = _Config.get_tb_config().g_wvd_serve
                client_ip = _Utils.flask_client_ip()
                headers = {"Content-Type": "application/json", "Authorization": _key}
                response = requests.post(
                    f"{g_wvd_serve}/predict",
                    json={"ip": client_ip, "data": "healthcheck"},
                    headers=headers,
                )
                data = response.json()
                if response.status_code == 200 and "threat_metrix" in data:
                    _Config.update_tb_config(
                        {
                            "g_serve_key": _key,
                        }
                    )
                    return True
                else:
                    return False
            else:
                return False
        except ConnectionError:
            logger.error("[x_x] Connection refused - Cannot connect to G-WVD")
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Validator.validate_key_auth", e
                )
            )

    def validate_protect_mode(_protect_mode) -> None:
        """
        It checks if the protect_mode is in the array arr_mode. If it is, it returns True. If it isn't,
        it returns False

        :param protect_mode: This is the mode that you want to run the script in
        :return: a boolean value.
        """
        try:
            arr_mode = ["off", "protection", "monitor"]
            if _protect_mode in arr_mode:
                return True
            else:
                logger.error(
                    "[x_x] Invalid Protect Mode. Protect mode must be: monitor - protection - off"
                )
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Validator.validate_protect_mode", e
                )
            )

    def validate_sensitive_value(_sensitive_value) -> None:
        """
        If the value is an integer between 0 and 100, return the integer. Otherwise, return 0

        :param sensitive_value: This is the value that will be used to determine if the user is
        sensitive to the keyword
        :return: the value of the sensitive_value variable.
        """
        try:
            if 0 <= int(_sensitive_value) <= 100:
                return True
            else:
                logger.error(
                    "[x_x] Invalid Sensitive Value. Sensitive value from 0 to 100"
                )
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Validator.validate_sensitive_value", e
                )
            )

    def validate_app_path(_app_path) -> None:
        try:
            regex = r"^[0-9a-f]{40}/gemini$"
            if re.match(regex, _app_path):
                return True
            else:
                logger.error(
                    "[x_x] Invalid Gemini App Path format. Gemini App Path like 0987654321/gemin "
                )
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Validator.validate_app_path", e
                )
            )

    def validate_dashboard_password(_password, _confirm_password) -> None:
        try:
            regex = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$"

            if re.match(regex, _password):
                return True
            else:
                logger.error(
                    "[x_x] Invalid Dashboard Password. Dashboard Password is Minimum eight characters, at least one letter, one number and one special character"
                )
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Validator.validate_dashboard_password", e
                )
            )

    def validate_notification_channel(_notification_channel) -> None:
        try:
            arr_noti_channel = ["off", "telegram", "slack", "mattermost"]
            if _notification_channel in arr_noti_channel:
                return True
            else:
                logger.error(
                    "[x_x] Invalid Notification Channel. Notification channel is Off - Telegram - Slack - Mattermost"
                )
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Validator.validate_notification_channel", e
                )
            )

    def validate_http_method(_http_method) -> None:
        """
        It checks if the HTTP method is valid

        :param http_method: The HTTP method to use
        :return: a boolean value.
        """
        try:
            arr_http_method = [
                "OPTIONS",
                "GET",
                "POST",
                "PUT",
                "DELETE",
                "TRACE",
                "CONNECT",
            ]
            if all(method in arr_http_method for method in _http_method):
                return True
            else:
                logger.error(
                    "[x_x] Invalid HTTP Method. HTTP Method must be: OPTIONS - GET - POST - PUT - DELETE - TRACE - CONNECT"
                )
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Validator.validate_http_method", e
                )
            )

    def validate_one_off_status(_on_off_status) -> None:
        try:
            arr_status = ["1", "0"]
            if _on_off_status in arr_status:
                return True
            else:
                logger.error(
                    "[x_x] Invalid Status. Safe Redirect or Protect Response Status must be: 1 - 0"
                )
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Validator.validate_safe_redirect_status", e
                )
            )

    def validate_trust_domain(_trust_domain_list) -> None:
        """
        This function validates a list of trust domains by checking if they are empty strings or if they
        match a regular expression for valid domain names.

        :param trust_domain_list: A list of strings representing trust domains that need to be validated
        :return: The function does not return anything explicitly, but it returns True if the
        trust_domain_list contains only empty strings or if all the domains in the list are valid
        according to the regular expression pattern. It returns False if any domain in the list is
        invalid according to the pattern. If an exception occurs, it logs an error message and does not
        return anything.
        """
        try:
            contains_only_empty_strings = all(
                element == "" for element in _trust_domain_list
            )
            if contains_only_empty_strings:
                return True
            else:
                for domain in _trust_domain_list:
                    if not re.match(
                        r"^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$", domain
                    ):
                        logger.error("[x_x] Invalid Domain Name")
                        return False
                    else:
                        return True
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Validator.validate_trust_domain", e
                )
            )

    def validator_g_wvd_serve(_serve, _key, _self_context=None) -> None:
        try:
            if re.match(r"https?://\S+", _serve):
                client_ip = None
                if _self_context:
                    client_ip = _Utils.socket_local_ip()
                else:
                    client_ip = _Utils.flask_client_ip()

                headers = {"Content-Type": "application/json", "Authorization": _key}
                response = requests.post(
                    f"{_serve}/predict",
                    json={"ip": client_ip, "data": "healthcheck"},
                    headers=headers,
                )
                data = response.json()

                if response.status_code == 200 and "threat_metrix" in data:
                    return True
                else:
                    logger.error(
                        "[x_x] Cannot connected to G-WVD serve. Check your G-WVD serve and G serve key"
                    )
                    return False
            else:
                return False
        except ConnectionError:
            logger.error("[x_x] Connection refused - Cannot connect to G-WVD")
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format(
                    "_Validator.validate_predict_server", e
                )
            )
