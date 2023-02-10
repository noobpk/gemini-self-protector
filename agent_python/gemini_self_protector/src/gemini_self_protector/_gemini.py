import os
import jwt
import yaml
from functools import wraps
from ._logger import logger
from flask import request, jsonify
from ._utils import _Utils
from ._template import _Template
from datetime import datetime, timezone
import secrets

# It's a class that contains a bunch of methods that are used to interact with the Gemini API
class _Gemini(object):
    def init_config(working_directory, config_content):
        """
        It takes a working directory and a dictionary of key-value pairs and updates the config.yml file
        in the working directory with the key-value pairs
        
        :param working_directory: The directory where the config.yml file is located
        :param config_content: This is the new data that you want to add to the YAML file
        """
        try:
            config_path = working_directory+'/config.yml'
            with open(config_path, "w") as file:
                yaml.dump(config_content, file)

        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
    
    def get_config(config_key):
        """
        It reads a config file and returns the value of the key that is passed to it
        
        :param config_key: The key you want to get the value of
        :return: The value of the key in the config.yml file.
        """
        try:
            running_directory = os.getcwd()
            gemini_working_directory = os.path.join(running_directory, r'gemini_protector')
            config_path = gemini_working_directory+'/config.yml'
            with open(config_path, "r") as file:
                config_data = yaml.safe_load(file)

            config_value = config_data["gemini-self-protector"][config_key]  
            return config_value
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def update_config(config_content):
        """
        The function takes a dictionary as an argument, and updates the YAML file with the new data
        
        :param config_content: This is the dictionary that contains the new configuration data
        """
        try:
            config_path = _Gemini.get_config('gemini_config_path')
            with open(config_path, "r") as file:
                config_data = yaml.safe_load(file)

            # Update the YAML data with the new data
            config_data["gemini-self-protector"].update(config_content)

            # Write the updated YAML data back to the file
            with open(config_path, "w") as file:
                yaml.dump(config_data, file)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def update_normal_request():
        try:
            current_value = _Gemini.get_config('gemini_normal_request')
            _Gemini.update_config({'gemini_normal_request': current_value+1})
            logger.info("[+] gemini_normal_request was updated")
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def update_abnormal_request():
        try:
            current_value = _Gemini.get_config('gemini_abnormal_request')
            _Gemini.update_config({'gemini_abnormal_request': current_value+1})
            logger.info("[+] gemini_abnormal_request was updated")
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def verify_license_key(license_key):
        try:
            if license_key:
                logger.info("[+] Gemini License Key: {}".format(license_key))
                if license_key == '988907ce-9803-11ed-a8fc-0242ac120002':
                    # call api and return access_token
                    access_token = jwt.encode(
                        {"license": license_key}, "secret", algorithm="HS256")
      
                    _Gemini.update_config({"gemini_license_key":license_key, "gemini_access_token": access_token})
                    return True
                else:
                    logger.error("[x_x] Invalid License Key")
                    return False
            else:
                return False
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
    
    def verify_protect_mode(protect_mode):
        """
        If the protect_mode is on, then it will return the protect_mode. If the protect_mode is monitor,
        then it will return the protect_mode. If the protect_mode is block, then it will return the
        protect_mode. If the protect_mode is off, then it will return the protect_mode. If the
        protect_mode is anything else, then it will return None.
        
        :param protect_mode: This is the mode in which the protector will run
        :return: The return value is the protect_mode variable.
        """
        try:
            global_protect_mode = None
            if protect_mode == 'on':
                logger.info("[+] Gemini-Self-Protector is On")
                global_protect_mode = protect_mode
            if protect_mode == 'monitor':
                logger.info("[+] Gemini-Self-Protector run on mode: MONITORING")
                global_protect_mode = protect_mode
            elif protect_mode == 'block':
                logger.info("[+] Gemini-Self-Protector run on mode: BLOCKING")
                global_protect_mode = protect_mode
            elif protect_mode == 'off':
                logger.info("[+] Gemini-Self-Protector is Off")
                global_protect_mode = protect_mode
            else:
                logger.error(
                    "[x_x] Invalid Protect Mode. Protect mode must be: on - monitor - block - off")
                logger.warning(
                    "[!] Your App Currently Running Without Gemini-Self-Protector.")
                global_protect_mode = None
            return global_protect_mode
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
    
    def verify_sensitive_value(sensitive_value):
        try:
            if 0 <= int(sensitive_value) <= 100:
                return int(sensitive_value)
            else:
                logger.error(
                    "[x_x] Invalid Sensitive Value. Sensitive value from 0 to 100")
                return 0
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
            _Gemini.update_config({"gemini_dashboard_path":dashboard_path})
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def init_gemini_dashboard_password():
        try:
            secret_password = secrets.token_hex(20)
            _Gemini.update_config({"gemini_dashboard_password":secret_password})
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))
    
    def load_gemini_log():
        log_path = _Gemini.get_config('gemini_log_path')
        with open(log_path+"/gemini_protetor_info.log") as f:
            logs = f.readlines()

        data_log = [log.strip().split(" - ") for log in logs]
        return data_log

    def __load_protect_flask__(gemini_protect_mode):
        try:
            # It's checking if the protect_mode is on. If it is, then it will return an error.
            if gemini_protect_mode == 'on':
                logger.error(
                    "[x_x] Protect mode for Method must be: monitor - block - off")
                pass
            elif gemini_protect_mode == 'monitor':
                logger.info("[+] Gemini-Self-Protector Mode MONITORING")
                # It's getting the sensitive value from the config.yml file.
                sensitive_value = _Gemini.get_config('gemini_sensitive_value')
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
                    _Gemini.update_normal_request()
                    return [status, current_time, ip_address, incident_id] 
                else:
                    status = True
                    _Gemini.update_abnormal_request()
                    return [status, ip_address, incident_id]
            elif gemini_protect_mode == 'block':
                logger.info("[+] Gemini-Self-Protector Mode BLOCKING")
                # It's getting the sensitive value from the config.yml file.
                sensitive_value = _Gemini.get_config('gemini_sensitive_value')
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
                incident_id = _Utils.generate_incident_id()
                # It's checking if the predict value is less than the sensitive value. If it is, then it
                # will return a status of True (safe). If it's not, then it will return a status of False (unsafe).
                if predict < sensitive_value: 
                    status = True
                    _Gemini.update_normal_request()
                    return [status, current_time, ip_address, incident_id] 
                else:
                    status = False
                    _Gemini.update_abnormal_request()
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
