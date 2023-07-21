import os
import re
import base64
import html
import urllib.parse
import requests
import uuid
import binascii
import jwt
from flask import request
from ._config import _Config
from ._logger import logger
from datetime import datetime, timezone


class _Utils(object):

    def decoder(string):
        """Decode a string using the specified encoding type."""

        # Remove the invalid escape sequences  - # Remove the backslash
        string = string.replace('\%', '%').replace(
            '\\', '').replace('<br/>', '')

        string = string.encode().decode('unicode_escape')

        string = urllib.parse.unquote(string)

        string = html.unescape(string)

        # Use a regular expression to find all base64-encoded segments in the string
        base64_pattern = r'( |,|;)base64,([A-Za-z0-9+/]*={0,2})'

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
                string = string.replace('\%', '%').replace(
                    '\\', '').replace('<br/>', '').replace(' ', '')
                match = re.search(base64_pattern, string)

                if match:
                    encoded_string = match.group(2)
                    try:
                        decoded_string = base64.b64decode(
                            encoded_string).decode()
                        string = string.replace(encoded_string, decoded_string)
                    except:
                        pass
            except:
                pass

        # Use a regular expression to find all url end with .js
        url_pattern = r'(?:https?://|//).+\.js'

        matches = re.findall(url_pattern, string)

        if matches:
            for match in matches:
                # alert('noobpk') - 5dc6f09bb9f90381814ff9fcbfe0a685
                string = string.replace(
                    match, ' 5dc6f09bb9f90381814ff9fcbfe0a685')

        # Lowercase string
        string = string.lower()

        # Use a regular expression to find all query
        sql_pattern = [
            r'(select.+)|(select.+(?:from|where|and).+)|(exec.+)'
            r".*--$"
        ]

        for pattern in sql_pattern:
            if re.search(pattern, string, re.IGNORECASE):
                # select * from noobpk; - 90e87fc8ba835e0d2bfeec5e3799ecfe
                string = string.replace(
                    match[0], ' 90e87fc8ba835e0d2bfeec5e3799ecfe')
                break

        string = string.encode('utf-7').decode()

        # Lowercase string
        string = string.lower()

        return string

    def web_vuln_detect_predict(payload) -> None:
        """
        It takes a payload as input and returns the accuracy of the prediction

        :param payload: The payload is the data that you want to send to the API. In this case, it's the
        data that you want to predict
        :return: The accuracy of the prediction.
        """
        try:
            predict_server = _Config.get_tb_config().predict_server
            predict_server_key_auth = _Config.get_tb_config().predict_server_key_auth
            headers = {"Content-Type": "application/json",
                       "Authorization": predict_server_key_auth}
            predict = requests.post(
                f'{predict_server}/predict', json={"data": payload}, headers=headers)
            if (predict):
                response = predict.json()
                accuracy = response.get('accuracy', 0)
                return accuracy
            else:
                logger.warning(
                    "[!] Cannot connect to predict server. Gemini-self protector cannot predit this request.")
                return 0
        except requests.exceptions.RequestException as e:
            logger.warning(
                "[!] Cannot connect to predict server. Gemini-self protector cannot predit this request.")
            return 0
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Utils.web_vuln_detect_predict', e))

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
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Utils.flask_client_ip', e))

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
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Utils.generate_event_id', e))

    def insident_ticket() -> None:
        try:
            time = datetime.now(timezone.utc)
            ip = _Utils.flask_client_ip()
            event_id = _Utils.generate_event_id()
            latitude = None
            longitude = None
            return {"Time": time, "IP": ip, "EventID": event_id, "Latitude": latitude, "Longitude": longitude}
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Utils.insident_ticket', e))

    def create_path() -> None:
        """
        It creates a random string of 20 characters and appends the string 'gemini' to it
        :return: A string
        """
        try:
            random = binascii.b2a_hex(os.urandom(20)).decode('utf-8')
            dashboard_path = str(random)+'/gemini'
            return dashboard_path
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Utils.create_path', e))

    def load_banner():
        print('''\033[1;31m \n
             __   ___                    __   ___       ___     __   __   __  ___  ___  __  ___  __   __  
            / _` |__   |\/| | |\ | |    /__` |__  |    |__     |__) |__) /  \  |  |__  /  `  |  /  \ |__) 
            \__> |___  |  | | | \| |    .__/ |___ |___ |       |    |  \ \__/  |  |___ \__,  |  \__/ |  \ 
                                        https://noobpk.github.io          #noobboy
                Real-time Protect Your Application - The Runtime Application Self Protection (RASP) Solution
        ''')
        print("")

    def predict_server_health() -> None:
        try:
            predict_server = _Config.get_tb_config().predict_server
            if predict_server:
                headers = {"Content-Type": "application/json"}
                response = requests.post(
                    f'{predict_server}/predict', json={"data": "healthcheck"}, headers=headers)
                if response and response.status_code == 200:
                    return True
                else:
                    return False
            return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Validator.predict_server_health', e))


class _Validator(object):

    def validate_key_auth(_key) -> None:
        try:
            if _key:
                predict_server = _Config.get_tb_config().predict_server
                headers = {"Content-Type": "application/json",
                           "Authorization": _key}
                response = requests.post(
                    f'{predict_server}/predict', json={"data": "healthcheck"}, headers=headers)
                data = response.json()
                if response.status_code == 200 and 'accuracy' in data:
                    _Config.update_tb_config({
                        'predict_server_key_auth': _key,
                    })
                    return True
                else:
                    return False
            else:
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Validator.validate_key_auth', e))

    def validate_protect_mode(protect_mode) -> None:
        """
        It checks if the protect_mode is in the array arr_mode. If it is, it returns True. If it isn't,
        it returns False

        :param protect_mode: This is the mode that you want to run the script in
        :return: a boolean value.
        """
        try:
            arr_mode = ['off', 'protection', 'monitor']
            if protect_mode in arr_mode:
                return True
            else:
                logger.error(
                    "[x_x] Invalid Protect Mode. Protect mode must be: monitor - protection - off")
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Validator.validate_protect_mode', e))

    def validate_sensitive_value(sensitive_value) -> None:
        """
        If the value is an integer between 0 and 100, return the integer. Otherwise, return 0

        :param sensitive_value: This is the value that will be used to determine if the user is
        sensitive to the keyword
        :return: the value of the sensitive_value variable.
        """
        try:
            if 0 <= int(sensitive_value) <= 100:
                return True
            else:
                logger.error(
                    "[x_x] Invalid Sensitive Value. Sensitive value from 0 to 100")
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Validator.validate_sensitive_value', e))

    def validate_app_path(app_path) -> None:
        try:
            regex = r"^[0-9a-f]{40}/gemini$"
            if re.match(regex, app_path):
                return True
            else:
                logger.error(
                    "[x_x] Invalid Gemini App Path format. Gemini App Path like 0987654321/gemin ")
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Validator.validate_app_path', e))

    def validate_dashboard_password(password, confirm_password) -> None:
        try:
            regex = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$"

            if re.match(regex, password):
                return True
            else:
                logger.error(
                    "[x_x] Invalid Dashboard Password. Dashboard Password is Minimum eight characters, at least one letter, one number and one special character")
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Validator.validate_dashboard_password', e))

    def validate_notification_channel(notification_channel) -> None:
        try:
            arr_noti_channel = ['disable', 'telegram', 'slack', 'mattermost']
            if notification_channel in arr_noti_channel:
                return True
            else:
                logger.error(
                    "[x_x] Invalid Notification Channel. Notification channel is Disable - Telegram - Slack - Mattermost")
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Validator.validate_notification_channel', e))

    def validate_http_method(http_method) -> None:
        """
        It checks if the HTTP method is valid

        :param http_method: The HTTP method to use
        :return: a boolean value.
        """
        try:
            arr_http_method = ['OPTIONS', 'GET', 'POST',
                               'PUT', 'DELETE', 'TRACE', 'CONNECT']
            if all(method in arr_http_method for method in http_method):
                return True
            else:
                logger.error(
                    "[x_x] Invalid HTTP Method. HTTP Method must be: OPTIONS - GET - POST - PUT - DELETE - TRACE - CONNECT")
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Validator.validate_http_method', e))

    def validate_one_off_status(on_off_status) -> None:
        try:
            arr_status = ['1', '0']
            if on_off_status in arr_status:
                return True
            else:
                logger.error(
                    "[x_x] Invalid Status. Safe Redirect or Protect Response Status must be: 1 - 0")
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Validator.validate_safe_redirect_status', e))

    def validate_trust_domain(trust_domain_list) -> None:
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
                element == '' for element in trust_domain_list)
            print(contains_only_empty_strings)
            if contains_only_empty_strings:
                return True
            else:
                for domain in trust_domain_list:
                    if not re.match(r'^[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$', domain):
                        logger.error(
                            "[x_x] Invalid Domain Name")
                        return False
                    else:
                        return True
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Validator.validate_trust_domain', e))

    def validate_predict_server(_server, _key) -> None:
        try:
            if re.match(r'https?://\S+', _server):
                headers = {"Content-Type": "application/json",
                           "Authorization": _key}
                response = requests.post(
                    f'{_server}/predict', json={"data": "healthcheck"}, headers=headers)
                data = response.json()
                if response.status_code == 200 and 'accuracy' in data:
                    return True
                else:
                    return False
            else:
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Validator.validate_predict_server', e))
