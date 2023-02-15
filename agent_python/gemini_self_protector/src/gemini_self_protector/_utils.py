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

    def web_vuln_detect_predict(payload):
        """
        It takes a payload as input and returns the accuracy of the prediction
        
        :param payload: The payload is the data that you want to send to the API. In this case, it's the
        data that you want to predict
        :return: The accuracy of the prediction.
        """
        headers = {"Content-Type": "application/json"}
        predict = requests.post(
            'https://web-vuln-detection.hptcybersec.com/predict', json={"data": payload}, headers=headers)
        response = predict.json()
        accuracy = response.get('accuracy')
        return accuracy

    def flask_client_ip():
        """
        If the request has a header called X-Forwarded-For, return the first value in the list of values
        for that header. Otherwise, return the remote address
        :return: The IP address of the client.
        """
        if request.headers.getlist("X-Forwarded-For"):
            return request.headers.getlist("X-Forwarded-For")[0]
        else:
            return request.remote_addr

    def generate_incident_id():
        """
        This function generates a random UUID and returns it
        :return: A random UUID.
        """
        incident_id = uuid.uuid4()
        return incident_id

    def insident_ticket():
        """
        It returns a list of three items: the IP address of the client, a unique incident ID, and the
        current time
        :return: A list of three items.
        """
        time = datetime.now(timezone.utc)
        ip = _Utils.flask_client_ip()
        incident_id = _Utils.generate_incident_id()
        return [time, ip, incident_id]

    def create_path():
        """
        It creates a random string of 20 characters and appends the string 'gemini' to it
        :return: A string
        """
        random = binascii.b2a_hex(os.urandom(20)).decode('utf-8')
        dashboard_path = str(random)+'/gemini'
        return dashboard_path
    
class _Validator(object):

    def validate_license_key(license_key):
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
      
                    _Config.update_config({"gemini_license_key":license_key, "gemini_access_token": access_token})
                    return True
                else:
                    logger.error("[x_x] Invalid License Key")
                    return False
            else:
                return False
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
    
    def validate_protect_mode(protect_mode):
        """
        The function takes a string as an argument, and checks if the string is in a list of strings. If
        it is, it returns the string. If it isn't, it returns None
        
        :param protect_mode: This is the mode of the protector
        :return: The protect mode is being returned.
        """
        """
        The function takes a string as an argument, and checks if the string is in a list of strings. If
        it is, it returns the string. If it isn't, it returns None
        
        :param protect_mode: This is the mode of the protector
        :return: The protect mode is being returned.
        """
        try:
            global_protect_mode = None
            arr_mode = ['monitor', 'block', 'off']
            if protect_mode not in arr_mode:
                logger.error(
                    "[x_x] Invalid Protect Mode. Protect mode must be: monitor - block - off")
                logger.warning(
                    "[!] Your App Currently Running Without Gemini-Self-Protector.")
            else:
                global_protect_mode = protect_mode
                logger.info("[+] Gemini-Self-Protector Mode: {}".format(global_protect_mode))
                return global_protect_mode
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
    
    def validate_sensitive_value(sensitive_value):
        """
        If the value is an integer between 0 and 100, return the integer. Otherwise, return 0
        
        :param sensitive_value: This is the value that will be used to determine if the user is
        sensitive to the keyword
        :return: the value of the sensitive_value variable.
        """
        try:
            if 0 <= int(sensitive_value) <= 100:
                return int(sensitive_value)
            else:
                logger.error(
                    "[x_x] Invalid Sensitive Value. Sensitive value from 0 to 100")
                return 0
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))