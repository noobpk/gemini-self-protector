import os
import re
import jwt
import yaml
from functools import wraps
from ._logger import logger
from flask import request, jsonify
from ._utils import _Utils, _Validator
from ._template import _Template
from ._config import _Config
from datetime import datetime, timezone
import secrets

# It's a class that contains a bunch of methods that are used to interact with the Gemini API
class _Gemini(object):
    def __init__(self) -> None:
        pass

    def init_gemini_config(working_directory):
        try:
            init_gemini_config_content = {
                'gemini-self-protector': {
                    'gemini_working_directory': working_directory,
                    'gemini_secret_key': str(os.urandom(24)),
                    'gemini_dashboard_path': None,
                    'gemini_config_path': working_directory+'/config.yml',
                    'gemini_log_path': working_directory+'/log',
                    'gemini_normal_request': 0,
                    'gemini_abnormal_request': 0,
                }
            }
            _Config(working_directory)
            _Config.init_config(init_gemini_config_content)

        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
    
    def get_gemini_config(config_key):

        try:
            _gemini_return = _Config.get_config(config_key)  
            return _gemini_return
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def update_gemini_config(config_content):

        try:
            _Config.update_config(config_content)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def __handle_normal_request__(payload, predit):
        try:
            current_value = _Gemini.get_gemini_config('gemini_normal_request')
            _Gemini.update_gemini_config({'gemini_normal_request': current_value+1})
            logger.info("[+] gemini_normal_request was updated")
            _Gemini.store_gemini_payload()
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def __handle_abnormal_request__():
        try:
            current_value = _Gemini.get_gemini_config('gemini_abnormal_request')
            _Gemini.update_gemini_config({'gemini_abnormal_request': current_value+1})
            logger.info("[+] gemini_abnormal_request was updated")

        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def validator_license_key(license_key):
        try:
            _Validator.validate_license_key(license_key)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
    
    def validator_protect_mode(protect_mode):
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
    
    def validator_sensitive_value(sensitive_value):
        try:
            _gemini_return = _Validator.validate_sensitive_value(sensitive_value)
            return _gemini_return
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def init_gemini_dashboard(flask_template_folder, flask_static_folder):
        try:
            _Template.gemini_template(flask_template_folder)
            _Template.gemini_static_file(flask_static_folder)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def init_gemini_dashboard_path():
        try:
            dashboard_path = _Utils.create_path()
            _Gemini.update_gemini_config({"gemini_dashboard_path":dashboard_path})
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def init_gemini_dashboard_password():
        try:
            secret_password = secrets.token_hex(20)
            _Gemini.update_gemini_config({"gemini_dashboard_password":secret_password})
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
    
    def load_gemini_log():
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

    def __load_protect_flask__(gemini_protect_mode):
        try:
            if gemini_protect_mode == 'monitor':
                logger.info("[+] Gemini-Self-Protector Mode MONITORING")
                # It's getting the sensitive value from the config.yml file.
                sensitive_value = _Gemini.get_gemini_config('gemini_sensitive_value')
                # It's getting the request body.
                data = request.data
                # It's decoding the request body.
                payload = _Utils.decoder(data.decode("utf-8"))
                # It's using the payload to predict if it's a web vulnerability or not.
                predict = _Utils.web_vuln_detect_predict(payload)
                logger.info("[+] Accuracy: {}".format(predict))

                # It's getting the current time, the IP address of the attacker, and generating an
                # incident ID.
                current_time = datetime.now(timezone.utc)
                ip_address = _Utils.flask_client_ip()
                incident_id = _Utils.generate_incident_id()
                
                if predict < sensitive_value:
                    status = True
                    _Gemini.__handle_normal_request__(data, predict)
                    return [status, current_time, ip_address, incident_id] 
                else:
                    status = True
                    _Gemini.__handle_abnormal_request__(data, predict)
                    return [status, ip_address, incident_id]
            elif gemini_protect_mode == 'block':
                logger.info("[+] Gemini-Self-Protector Mode BLOCKING")
                # It's getting the sensitive value from the config.yml file.
                sensitive_value = _Gemini.get_gemini_config('gemini_sensitive_value')
                # It's getting the request body.
                data = request.data
                # It's decoding the request body.
                payload = _Utils.decoder(data.decode("utf-8"))
                # It's using the payload to predict if it's a web vulnerability or not.
                predict = _Utils.web_vuln_detect_predict(payload)
                logger.info("[+] Accuracy: {}".format(predict))

                # It's getting the current time, the IP address of the attacker, and generating an
                # incident ID.
                current_time = datetime.now(timezone.utc)
                ip_address = request.remote_addr
                incident_id = _Utils.generate_incident_id(data, predict)
                # It's checking if the predict value is less than the sensitive value. If it is, then it
                # will return a status of True (safe). If it's not, then it will return a status of False (unsafe).
                if predict < sensitive_value: 
                    status = True
                    _Gemini.__handle_normal_request__(data, predict)
                    return [status, current_time, ip_address, incident_id] 
                else:
                    status = False
                    _Gemini.__handle_abnormal_request__()
                    return [status, current_time, ip_address, incident_id] 
            elif gemini_protect_mode == 'off':
                logger.info("[+] Gemini-Self-Protector is Off")
                pass
            else:
                logger.error(
                    "[x_x] Invalid Protect Mode. Protect mode must be: monitor - block - off")
                pass
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
