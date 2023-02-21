import os
import json
from functools import wraps
from ._logger import logger
from flask import request
from ._utils import _Utils, _Validator
from ._template import _Template
from ._config import _Config
from ._protect import _Protect
from datetime import datetime, timezone
import secrets

# It's a class that contains a bunch of methods that are used to interact with the Gemini API
class _Gemini(object):

    def init_gemini_config(working_directory):
        """
        It creates a config file in the working directory with the following content:
        :param working_directory: The directory where the gemini-self-protector is installed
        """
        try:
            init_gemini_config_content = {
                'gemini-self-protector': {
                    'gemini_working_directory': working_directory,
                    'gemini_secret_key': str(os.urandom(24)),
                    'gemini_dashboard_path': None,
                    'gemini_config_path': working_directory+'/config.yml',
                    'gemini_data_store_path': working_directory+'/data.json',
                    'gemini_acl_path': working_directory+'/acl.json',
                    'gemini_log_path': working_directory+'/log',
                    'gemini_normal_request': 0,
                    'gemini_abnormal_request': 0,
                    'gemini_global_protect_mode': 'monitor',
                    'gemini_sensitive_value': 50,
                    'gemini_max_content_length': 52428800, # 50 * 1024 * 1024 = 50MB
                    'gemini_http_method_allow': ['OPTIONS', 'GET', 'POST', 'PUT', 'DELETE'],
                    'gemini_safe_redirect': 'on',
                    'gemini_trust_domain': ['localhost'],
                }
            }
            _Config(working_directory, init_gemini_config_content)

        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def get_gemini_config(config_key) -> None:
        """
        This function is used to get the value of a key from the config file

        :param config_key: The key you want to get the value for
        :return: _gemini_return
        """
        try:
            _gemini_return = _Config.get_config(config_key)
            return _gemini_return
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def update_gemini_config(config_content):
        """
        It takes a dictionary as an argument and updates the config file with the values in the
        dictionary

        :param config_content: This is the content of the config file
        """
        try:
            _Config.update_config(config_content)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def init_gemini_data_store(working_directory):
        """
        This function initializes the data store for the gemini package

        :param working_directory: This is the directory where you want to store your data
        """
        try:
            _Config.init_data_store(working_directory)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def update_gemini_data_store(_dict):
        """
        It takes a dictionary as an argument, and then calls a function from another module, which takes
        the dictionary as an argument

        :param _dict: This is a dictionary that contains the following keys:
        """
        try:
            _Config.update_data_store(_dict)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def init_gemini_acl(working_directory):
        """
        The function is used to initialize the ACL file for the gemini project

        :param working_directory: The directory where the gemini_acl.yaml file is located
        """
        try:
            _Config.init_acl(working_directory)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def update_gemini_acl(_dict):
        """
        It takes a dictionary as an argument, and then it updates the ACLs in the config file

        :param _dict: This is a dictionary that contains the following keys:
        """
        try:
            _Config.update_acl(_dict)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def load_gemini_acl() -> None:
        """
        It reads a JSON file, and returns a list of dictionaries containing the two columns
        :return: A list of dictionaries containing the three columns
        """
        try:
            data_store_path = _Gemini.get_gemini_config('gemini_acl_path')
            # Load the JSON data from a file
            with open(data_store_path, 'r') as f:
                data = json.load(f)

            # Create a list of dictionaries containing the three columns
            rows = [{'Time': d['Time'], 'Ip': d['Ip']} for d in data['gemini_acl']]
            return rows

        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def check_gemini_acl(_ip_address) -> None:
        """
        This function checks if the IP address is in the ACL list. If it is, it will return True,
        otherwise it will return False

        :param ip: The IP address of the client
        """
        try:
           return _Config.check_acl(_ip_address)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def remove_gemini_acl(_ip_address):
        try:
            _Config.remove_acl(_ip_address)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def validator_license_key(license_key):
        """
        It takes a license key as an argument and validates it

        :param license_key: The license key you received from the license server
        """
        try:
            _Validator.validate_license_key(license_key)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def validator_protect_mode(protect_mode) -> None:
        """
        The function takes a string as an argument, and checks if the string is in a list of strings. If
        it is, it returns the string. If it isn't, it returns None

        :param protect_mode: This is the mode of the protector
        :return: The protect mode is being returned.
        """
        try:
            _gemini_return = _Validator.validate_protect_mode(protect_mode)
            return _gemini_return
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def validator_http_method(http_method):
        try:
           _gemini_return = _Validator.validate_http_method(http_method)
           return _gemini_return
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def validator_sensitive_value(sensitive_value) -> None:
        """
        The function validator_sensitive_value() takes in a sensitive value and returns a boolean value

        :param sensitive_value: The value to be validated
        :return: The return value is a dictionary.
        """
        try:
            _gemini_return = _Validator.validate_sensitive_value(sensitive_value)
            return _gemini_return
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def init_gemini_dashboard(flask_template_folder, flask_static_folder):
        """
        It takes the path to the template folder and static folder of the flask app and copies the
        gemini dashboard template and static files to the respective folders

        :param flask_template_folder: The folder where you want to store the templates
        :param flask_static_folder: The folder where you want to store the static files
        """
        try:
            _Template.gemini_template(flask_template_folder)
            _Template.gemini_static_file(flask_static_folder)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def init_gemini_dashboard_path():
        """
        It creates a path for the dashboard and updates the gemini config file with the path
        """
        try:
            dashboard_path = _Utils.create_path()
            _Gemini.update_gemini_config({"gemini_dashboard_path":dashboard_path})
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def init_gemini_dashboard_password():
        """
        It generates a random password and stores it in the config file
        """
        try:
            secret_password = secrets.token_hex(20)
            _Gemini.update_gemini_config({"gemini_dashboard_password":secret_password})
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def load_gemini_log() -> None:
        """
        It reads the log file and returns a list of dictionaries
        :return: A list of dictionaries.
        """
        try:
            log_path = _Gemini.get_gemini_config('gemini_log_path')
            data_log = []
            with open(log_path+"/gemini_protetor_info.log") as f:
                for line in f:
                    parts = line.strip().split(' - ')
                    if len(parts) != 3:
                        continue
                    data_log.append({
                        'time': parts[0],
                        'status': parts[1],
                        'message': parts[2],
                    })
            return data_log
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def load_gemini_data_store() -> None:
        """
        It reads a JSON file, creates a list of dictionaries containing the three columns, sorts the
        list by Time in descending order, and returns the sorted list
        :return: A list of dictionaries containing the three columns
        """
        try:
            data_store_path = _Gemini.get_gemini_config('gemini_data_store_path')
            # Load the JSON data from a file
            with open(data_store_path, 'r') as f:
                data = json.load(f)

            # Create a list of dictionaries containing the three columns
            rows = [{'Time': d['Time'], 'Request': d['Request'], 'AttackType': d['AttackType'], 'Predict': d['Predict'], 'IncidentID': d['IncidentID']} for d in data['gemini_data_stored']]
            # Sort the list by Time in descending order
            rows = sorted(rows, key=lambda x: datetime.strptime(x['Time'], '%Y-%m-%d %H:%M:%S'), reverse=True)
            return rows

        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def get_flask_client_ip() -> None:
        """
        It returns the client IP address of the user who is accessing the Flask application
        :return: The IP address of the client.
        """
        try:
            return _Utils.flask_client_ip()
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def generate_insident_ticket() -> None:
        try:
            return _Utils.insident_ticket()
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def __load_protect_flask_request__(gemini_protect_mode) -> None:
        """
        This function is used to load the flask protect mode

        :param gemini_protect_mode: This is the mode that you want to use to protect your flask app
        :return: The function _Protect.protect_flask(gemini_protect_mode)
        """
        try:
            return _Protect.__protect_flask_request__(gemini_protect_mode)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def __load_protect_flask_response__(original_response, gemini_protect_mode) -> None:
        try:
            safe_redirect = _Gemini.get_gemini_config('gemini_safe_redirect')
            return _Protect.__protect_flask_response__(safe_redirect, original_response, gemini_protect_mode)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def make_secure_response_header(response) -> None:
        try:
            return _Protect.__secure_response_header__(response)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
