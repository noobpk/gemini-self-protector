import os
import json
from functools import wraps
from ._logger import logger
from flask import request
from ._utils import _Utils, _Validator
from ._template import _Template
from ._config import _Config
from ._protect import _Protect
from ._audit import _Audit
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
                    'gemini_install': False,
                    'gemini_license_key': None,
                    'gemini_access_token': None,
                    'gemini_working_directory': working_directory,
                    'gemini_secret_key': str(os.urandom(24)),
                    'gemini_app_path': None,
                    'gemini_app_username': 'superadmin',
                    'gemini_config_path': working_directory+'/config.yml',
                    'gemini_data_store_path': working_directory+'/data.json',
                    'gemini_acl_path': working_directory+'/acl.json',
                    'gemini_log_path': working_directory+'/log',
                    'gemini_audit_dependency': working_directory+'/audit-dependency.json',
                    'gemini_total_request': 0,
                    'gemini_normal_request': 0,
                    'gemini_abnormal_request': 0,
                    'gemini_global_protect_mode': 'monitor',
                    'gemini_sensitive_value': 50,
                    'gemini_max_content_length': 52428800,  # 50 * 1024 * 1024 = 50MB
                    'gemini_http_method_allow': ['OPTIONS', 'GET', 'POST', 'PUT', 'DELETE'],
                    'gemini_safe_redirect': 'off',
                    'gemini_trust_domain': [],
                    'gemini_cors': {
                        'origin': '*',
                        'methods': '*',
                        'credentials': True,
                        'headers': ['Content-Type']
                    },
                    'gemini_server_name': 'gemini',
                    'gemini_notification_channel': 'disable',
                    'gemini_telegram_token': None,
                    'gemini_telegram_chat_id': None,
                    'gemini_notification_webhook': None,
                    'gemini_predict_server': 'http://127.0.0.1:5000'
                }
            }
            _Config(working_directory, init_gemini_config_content)

        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.init_gemini_config', e))

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
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.get_gemini_config', e))

    def update_gemini_config(config_content):
        """
        It takes a dictionary as an argument and updates the config file with the values in the
        dictionary

        :param config_content: This is the content of the config file
        """
        try:
            _Config.update_config(config_content)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.update_gemini_config', e))

    def init_gemini_data_store(working_directory):
        """
        This function initializes the data store for the gemini package

        :param working_directory: This is the directory where you want to store your data
        """
        try:
            _Config.init_data_store(working_directory)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.init_gemini_data_store', e))

    def update_gemini_data_store(_dict):
        """
        It takes a dictionary as an argument, and then calls a function from another module, which takes
        the dictionary as an argument

        :param _dict: This is a dictionary that contains the following keys:
        """
        try:
            _Config.update_data_store(_dict)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.update_gemini_data_store', e))

    def init_gemini_acl(working_directory):
        """
        The function is used to initialize the ACL file for the gemini project

        :param working_directory: The directory where the gemini_acl.yaml file is located
        """
        try:
            _Config.init_acl(working_directory)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.init_gemini_acl', e))

    def update_gemini_acl(_dict) -> None:
        """
        It takes a dictionary as an argument, and then it updates the ACLs in the config file

        :param _dict: This is a dictionary that contains the following keys:
        """
        try:
            return _Config.update_acl(_dict)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.update_gemini_acl', e))

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
            rows = [{'Time': d['Time'], 'Ip': d['Ip'], 'Access': d['Access'], 'Desciption': d['Desciption']}
                    for d in data['gemini_acl']]
            return rows

        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.load_gemini_acl', e))

    def check_gemini_acl(_ip_address) -> None:
        """
        This function checks if the IP address is in the ACL list. If it is, it will return True,
        otherwise it will return False

        :param ip: The IP address of the client
        """
        try:
           return _Config.check_acl(_ip_address)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.check_gemini_acl', e))

    def remove_gemini_acl(_ip_address):
        try:
            _Config.remove_acl(_ip_address)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.remove_gemini_acl', e))

    def init_gemini_audit_dependency(working_directory):
        try:
            _Config.init_audit_dependency(working_directory)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.init_gemini_audit_dependency', e))

    def validator_license_key(license_key):
        """
        It takes a license key as an argument and validates it

        :param license_key: The license key you received from the license server
        """
        try:
            _gemini_return = _Validator.validate_license_key(license_key)
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.validator_license_key', e))

    def is_valid_license_key() -> None:
        """
        This function attempts to validate a license key and logs an error message if an exception
        occurs.
        :return: the output of the `_Validator.is_valid_license_key()` method, which is not specified in
        the code provided. The return type is also not specified, but it is assumed to be a boolean
        value since the method name suggests that it is checking if a license key is valid or not.
        """
        try:
            _gemini_return = _Validator.is_valid_license_key()
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.is_valid_license_key', e))

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
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.validator_protect_mode', e))

    def validator_http_method(http_method):
        """
        The function validator_http_method() takes in a string as an argument and returns a boolean
        value

        :param http_method: The HTTP method to be used for the request
        :return: The return value is a dictionary.
        """
        try:
           _gemini_return = _Validator.validate_http_method(http_method)
           return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.validator_http_method', e))

    def validator_sensitive_value(sensitive_value) -> None:
        """
        The function validator_sensitive_value() takes in a sensitive value and returns a boolean value

        :param sensitive_value: The value to be validated
        :return: The return value is a dictionary.
        """
        try:
            _gemini_return = _Validator.validate_sensitive_value(
                sensitive_value)
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.validator_sensitive_value', e))

    def validator_app_path(app_path) -> None:
        try:
            _gemini_return = _Validator.validate_app_path(
                app_path)
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.validator_app_path', e))

    def validator_notification_channel(notification_channel) -> None:
        try:
            _gemini_return = _Validator.validate_notification_channel(
                notification_channel)
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.validator_notification_channel', e))

    def validator_dashboard_password(password, confirm_password) -> None:
        try:
            _gemini_return = _Validator.validate_dashboard_password(
                password, confirm_password)
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.validator_dashboard_password', e))

    def validator_safe_redirect_status(safe_redirect_status) -> None:
        """
        This function validates a safe redirect status and logs an error message if an exception occurs.
        
        :param safe_redirect_status: The parameter `safe_redirect_status` is expected to be passed to
        the function `validator_safe_redirect_status` as an argument. It is not clear from the code
        snippet what data type this parameter should be, but it is likely that it should be a string or
        an integer representing an HTTP status code
        :return: the output of the `_Validator.validate_safe_redirect_status` function, which is not
        specified in the given code snippet. If an exception is raised, the function logs an error
        message. However, the function itself does not have a return statement for cases where an
        exception is not raised.
        """
        try:
            _gemini_return = _Validator.validate_safe_redirect_status(
                safe_redirect_status)
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.validator_safe_redirect_status', e))

    def validator_trust_domain(trust_domain_list):
        """
        The function validator_trust_domain() takes a list of trust domains as an argument and returns a
        list of trust domains that are valid

        :param trust_domain_list: A list of trust domains
        :return: The return is a list of dictionaries.
        """
        try:
            _gemini_return = _Validator.validate_trust_domain(
                trust_domain_list)
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.validator_trust_domain', e))

    def handler_cli_license_key():
        try:
            isKey = _Gemini.get_gemini_config('gemini_license_key')
            if isKey is None:
                while True:
                    try:
                        key = input("Please enter your license key: ")
                    except Exception as e:
                        logger.error(
                            "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.handler_cli_license_key', e))
                        continue
                    else:
                        break

                if _Gemini.validator_license_key(key):
                    logger.info(
                        "[+] License Activate Successful. Thank for using Gemini-Self Protector")
                else:
                    _Gemini.handler_cli_license_key()
            else:
                logger.info(
                    "[+] Verify license key.....")
                if _Gemini.validator_license_key(isKey):
                    logger.info(
                        "[+] Verify license key successful")
                else:
                    while True:
                        try:
                            key = input("Please update your license key: ")
                        except Exception as e:
                            logger.error(
                                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.handler_cli_license_key', e))
                            continue
                        else:
                            break

                    if _Gemini.validator_license_key(key):
                        logger.info(
                            "[+] License Activate Successful. Thank for using Gemini-Self Protector")
                    else:
                        _Gemini.handler_cli_license_key()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.handler_cli_license_key', e))

    def init_gemini_dashboard(flask_template_folder, flask_static_folder):
        """
        This function initializes the Gemini dashboard by initializing the Gemini template and static
        folders.
        
        :param flask_template_folder: The parameter `flask_template_folder` is a string that represents
        the path to the folder where Flask templates are stored. Flask templates are used to generate
        HTML pages dynamically
        :param flask_static_folder: The flask_static_folder parameter is a string that represents the
        path to the folder where the static files for the Flask application are stored. These static
        files can include images, CSS files, and JavaScript files that are used by the application
        """

        try:
            _Template.init_gemini_template(flask_template_folder)
            _Template.init_gemini_static(flask_static_folder)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.init_gemini_dashboard', e))

    def init_gemini_app_path():
        """
        It creates a path for the gemini app and updates the gemini config file with the path
        """
        try:
            gemimi_app_path = _Utils.create_path()
            _Gemini.update_gemini_config(
                {"gemini_app_path": gemimi_app_path})
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.init_gemini_app_path', e))

    def load_gemini_log() -> None:
        """
        It reads the log file and returns a list of dictionaries
        :return: A list of dictionaries.
        """
        try:
            log_path = _Gemini.get_gemini_config('gemini_log_path')
            data_log = []
            with open(log_path+"/gemini-protetor-info.log") as f:
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
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.load_gemini_log', e))

    def load_gemini_data_store() -> None:
        """
        It reads a JSON file, creates a list of dictionaries containing the three columns, sorts the
        list by Time in descending order, and returns the sorted list
        :return: A list of dictionaries containing the three columns
        """
        try:
            data_store_path = _Gemini.get_gemini_config(
                'gemini_data_store_path')
            # Load the JSON data from a file
            with open(data_store_path, 'r') as f:
                data = json.load(f)

            # Create a list of dictionaries containing the three columns
            rows = [{'Time': d['Time'], 'Request': d['Request'], 'AttackType': d['AttackType'],
                     'Predict': d['Predict'], 'IncidentID': d['IncidentID']} for d in data['gemini_data_stored']]
            # Sort the list by Time in descending order
            rows = sorted(rows, key=lambda x: datetime.strptime(
                x['Time'], '%Y-%m-%d %H:%M:%S'), reverse=True)
            return rows

        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.load_gemini_data_store', e))

    def get_flask_client_ip() -> None:
        """
        It returns the client IP address of the user who is accessing the Flask application
        :return: The IP address of the client.
        """
        try:
            return _Utils.flask_client_ip()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.get_flask_client_ip', e))

    def generate_insident_ticket() -> None:
        """
        It generates a ticket number for an incident
        :return: the value of the function _Utils.insident_ticket()
        """
        try:
            return _Utils.insident_ticket()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.generate_insident_ticket', e))

    def __load_protect_flask_request__(gemini_protect_mode) -> None:
        """
        This function is used to load the flask protect mode

        :param gemini_protect_mode: This is the mode that you want to use to protect your flask app
        :return: The function _Protect.protect_flask(gemini_protect_mode)
        """
        try:
            return _Protect.__protect_flask_request__(gemini_protect_mode)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.__load_protect_flask_request__', e))

    def __load_protect_flask_response__(original_response, gemini_protect_mode) -> None:
        """
        This function is used to protect the flask response

        :param original_response: The original response from the Flask app
        :param gemini_protect_mode: This is the mode that you want to use to protect your application
        :return: the result of the function call to __protect_flask_response__.
        """
        try:
            safe_redirect = _Gemini.get_gemini_config('gemini_safe_redirect')
            return _Protect.__protect_flask_response__(safe_redirect, original_response, gemini_protect_mode)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.__load_protect_flask_response__', e))

    def make_secure_response_header(response) -> None:
        """
        It makes the response header secure.

        :param response: The response object that is returned by the view function
        :return: the response header.
        """
        try:
            return _Protect.__secure_response_header__(response)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.make_secure_response_header', e))

    def make_secure_cookie(app):
        try:
            _Protect.__secure_cookie__(app)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.make_secure_cookie', e))

    def get_dependency_file():
        """
        It will try to find the requirements.txt file in the current directory and if it doesn't find
        it, it will throw an exception
        :return: the file path of the requirements.txt file.
        """
        try:
            return _Audit.__find_requirements_file__()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.get_dependency_file', e))

    def __audit_dependency_vulnerability__(file_path):
        """
        This function will take a file path as an argument and will call the
        __dependency_vulnerability__ function from the _Audit class

        :param file_path: The path to the file you want to audit
        """
        try:
            _Audit.__dependency_vulnerability__(file_path)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.__audit_dependency_vulnerability__', e))

    def load_gemini_dependency_result() -> None:
        """
        This function loads a JSON file containing dependency audit results from a specified path.
        :return: The function is supposed to return a JSON object loaded from a file, but it is not
        actually returning anything. The return statement is inside the try block, so if an exception is
        raised, the function will exit without returning anything. To fix this, the return statement
        should be moved outside the try block, or the function should raise an exception if the file
        cannot be loaded.
        """
        try:
            dependency_result_path = _Gemini.get_gemini_config(
                'gemini_audit_dependency')
            # Load the JSON data from a file
            with open(dependency_result_path, 'r') as f:
                data = json.load(f)
            return data
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.load_gemini_dependency_result', e))

    def get_gemini_banner():
        """
        The function attempts to load a banner using a utility function and logs an error message if an
        exception occurs.
        """
        try:
            _Utils.load_banner()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.get_gemini_banner', e))

    def calulate_total_access():
        """
        This function calculates the total number of requests made to a Gemini application, excluding
        certain paths.
        :return: In the given code, the function `calulate_total_access()` returns `None` if the
        condition `request.path.startswith(f"/{app_path}") or ignored_keyword in request.path` is true,
        otherwise it does not return anything.
        """
        try:
            app_path = _Gemini.get_gemini_config('gemini_app_path')
            ignored_keyword = "gemini-protector-static"

            if request.path.startswith(f"/{app_path}") or ignored_keyword in request.path:
                return None

            current_access = _Gemini.get_gemini_config('gemini_total_request')
            current_access += 1
            _Gemini.update_gemini_config(
                {"gemini_total_request": current_access})
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.calulate_total_access', e))

    def check_predict_server() -> None:
        try:
            return _Utils.predict_server_status()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.check_predict_server', e))
