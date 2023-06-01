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

    def decoder(string) -> None:
        """
        It takes a string, decodes it from a variety of encoding types, and then returns the decoded
        string

        :param string: The string to decode
        :return: The decoded string
        """
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
        sql_pattern = r'(select.+)|(select.+(?:from|where|and).+)|(exec.+)'

        match = re.search(sql_pattern, string)

        if match:
            # select * from noobpk; - 90e87fc8ba835e0d2bfeec5e3799ecfe
            string = string.replace(
                match[0], ' 90e87fc8ba835e0d2bfeec5e3799ecfe')

        string = string.encode('utf-7').decode()

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
            headers = {"Content-Type": "application/json"}
            predict = requests.post(
                'https://web-vuln-detection.onrender.com/predict', json={"data": payload}, headers=headers)
            response = predict.json()
            accuracy = response.get('accuracy')
            return accuracy
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

    def generate_incident_id() -> None:
        """
        This function generates a random UUID and returns it
        :return: A random UUID.
        """
        try:
            incident_id = uuid.uuid4()
            return incident_id
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Utils.generate_incident_id', e))

    def insident_ticket() -> None:
        """
        It returns a list of three items: the IP address of the client, a unique incident ID, and the
        current time
        :return: A list of three items.
        """
        try:
            time = datetime.now(timezone.utc)
            ip = _Utils.flask_client_ip()
            incident_id = _Utils.generate_incident_id()
            return {"Time": time, "IP": ip, "IncidentID": incident_id}
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


class _Validator(object):

    def validate_license_key(license_key) -> None:
        """
        If the license key is valid, then update the config file with the license key and the access
        token

        :param license_key: The license key that you received from the API
        :return: True or False
        """
        try:
            if license_key:
                if license_key == '988907ce-9803-11ed-a8fc-0242ac120002':
                    # call api and return access_token
                    access_token = jwt.encode(
                        {"license": license_key}, "secret", algorithm="HS256")

                    _Config.update_config(
                        {"gemini_license_key": license_key, "gemini_access_token": access_token})
                    return True
                else:
                    logger.error("[x_x] Invalid License Key")
                    return False
            else:
                logger.error("[x_x] Invalid License Key")
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Validator.validate_license_key', e))

    def validate_protect_mode(protect_mode) -> None:
        """
        It checks if the protect_mode is in the array arr_mode. If it is, it returns True. If it isn't,
        it returns False

        :param protect_mode: This is the mode that you want to run the script in
        :return: a boolean value.
        """
        try:
            arr_mode = ['off', 'block', 'monitor']
            if protect_mode in arr_mode:
                return True
            else:
                logger.error(
                    "[x_x] Invalid Protect Mode. Protect mode must be: monitor - block - off")
                return True
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

    def validate_safe_redirect_status(safe_redirect_status) -> None:
        """
        If the value of safe_redirect_status is in the array arr_status, return True, else return False.

        :param safe_redirect_status: This is the status of the safe redirect. It can be either on or off
        :return: True or False
        """
        try:
            arr_status = ['on', 'off']
            if safe_redirect_status in arr_status:
                return True
            else:
                logger.error(
                    "[x_x] Invalid Safe Redirect Status. Safe Redirect Status must be: ON - OFF")
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Validator.validate_safe_redirect_status', e))

    def validate_trust_domain(trust_domain_list) -> None:
        try:
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
