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


class _Gemini(object):

    def init_gemini_database(_working_directory):
        try:
            _Config(_working_directory)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.update_gemini_config', e))

    def get_gemini_config() -> None:
        try:
            _gemini_return = _Config.get_tb_config()
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.get_gemini_config', e))

    def update_gemini_config(_update_content):
        try:
            _Config.update_tb_config(_update_content)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.update_gemini_config', e))

    def get_gemini_user() -> None:
        try:
            _gemini_return = _Config.get_tb_user()
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.get_gemini_user', e))

    def update_gemini_user(update_content):
        try:
            _Config.update_tb_user(update_content)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.update_gemini_user', e))

    def get_gemini_summary() -> None:
        try:
            _gemini_return = _Config.get_tb_summary()
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.get_gemini_summary', e))

    def update_gemini_summary(update_content):
        try:
            _Config.update_tb_summary(update_content)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.update_gemini_summary', e))

    def get_gemini_request_log() -> None:
        try:
            _gemini_return = _Config.get_tb_request_log()
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.get_gemini_summary', e))

    def get_gemini_detail_request_log(_event_id) -> None:
        try:
            _gemini_return = _Config.get_tb_request_log_first(_event_id)
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.get_gemini_detail_request_log', e))

    def store_gemini_request_log(ipaddress, url, request, response, attack_type, predict, event_id, latitude, longitude):
        try:
            _Config.store_tb_request_log(ipaddress, url, request, response, attack_type, predict, event_id, latitude, longitude)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.store_gemini_request_log', e))

    def update_gemini_request_log(_event_id):
        try:
            _Config.update_record_request_log(_event_id)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.update_gemini_request_log', e))

    def get_gemini_acl():
        try:
            _gemini_return = _Config.get_tb_acl()
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.get_gemini_acl', e))

    def store_gemini_acl(ipaddress, isallow, desciption):
        try:
            _Config.store_tb_acl(ipaddress, isallow, desciption)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.store_gemini_acl', e))

    def check_gemini_acl(_ip_address) -> None:
        try:
            return _Config.check_acl(_ip_address)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.check_gemini_acl', e))

    def remove_gemini_acl(_ip_address):
        try:
            _Config.remove_record_acl(_ip_address)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.remove_gemini_acl', e))

    def get_gemini_audit_dependency() -> None:
        try:
            _gemini_return = _Config.get_tb_dependency()
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.get_gemini_audit_dependency', e))

    def get_gemini_feedback() -> None:
        try:
            _gemini_return = _Config.get_tb_feedback()
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.get_gemini_feedback', e))

    def store_gemini_feedback(_sentence, _label):
        try:
            _Config.store_tb_feedback(_sentence, _label)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.store_gemini_feedback', e))

    def export_gemini_feedback() -> str:
        try:
            _gemini_return = _Config.export_tb_feedback()
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.export_gemini_feedback', e))


    def validator_key_auth(_key):
        try:
            _gemini_return = _Validator.validate_key_auth(_key)
            return _gemini_return
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.validator_key_auth', e))

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

    def validator_on_off_status(on_off_status) -> None:
        try:
            _gemini_return = _Validator.validate_one_off_status(
                on_off_status)
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
                {"app_path": gemimi_app_path})
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
        It generates a ticket number for an event
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
            safe_redirect = _Gemini.get_gemini_config().safe_redirect
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
            app_path = _Gemini.get_gemini_config().app_path
            ignored_keyword = "gemini-protector-static"

            if request.path.startswith(f"/{app_path}") or ignored_keyword in request.path:
                return None

            current_access = _Gemini.get_gemini_summary().total_request
            current_access += 1
            _Gemini.update_gemini_summary(
                {"total_request": current_access})
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.calulate_total_access', e))

    def health_check_predict_server() -> None:
        try:
            return _Utils.predict_server_health()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.check_predict_server', e))

    def validator_predict_server(_server, _key) -> None:
        try:
            return _Validator.validate_predict_server(_server, _key)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.validator_predict_server', e))

    def __load_mini_anti_dos__() -> None:
        try:
            return _Protect.__handle_mini_anti_dos__()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini.__load_mini_anti_dos__', e))        