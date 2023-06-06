import os
from ._gemini import _Gemini
from ._gui import _Gemini_GUI
from functools import wraps
from flask import Flask, Blueprint, request, make_response, render_template, session, redirect, url_for, flash
from ._logger import logger
import ipaddress
from datetime import datetime, timezone


class GeminiManager(object):

    def __init__(self, flask_app: Flask = None):

        _Gemini.get_gemini_banner()

        # This is creating a directory called gemini-protector in the current working directory.
        running_directory = os.getcwd()
        gemini_working_directory = os.path.join(
            running_directory, r'gemini-protector')
        if not os.path.exists(gemini_working_directory):
            os.makedirs(gemini_working_directory)

        if not os.path.isfile(gemini_working_directory+'/config.yml'):
            _Gemini.init_gemini_config(gemini_working_directory)

        if flask_app is not None:
            logger.info(
                "[+] Running gemini-self protector with GUI")
            _Gemini_GUI(flask_app)

            if not os.path.isfile(gemini_working_directory+'/data.json'):
                _Gemini.init_gemini_data_store(gemini_working_directory)

            if not os.path.isfile(gemini_working_directory+'/acl.json'):
                _Gemini.init_gemini_acl(gemini_working_directory)

            if not os.path.isfile(gemini_working_directory+'/audit-dependency.json'):
                _Gemini.init_gemini_audit_dependency(gemini_working_directory)
        else:
            logger.info(
                "[+] Running gemini-self protector without GUI")
            if not os.path.isfile(gemini_working_directory+'/data.json'):
                _Gemini.init_gemini_data_store(gemini_working_directory)

            if not os.path.isfile(gemini_working_directory+'/acl.json'):
                _Gemini.init_gemini_acl(gemini_working_directory)

            if not os.path.isfile(gemini_working_directory+'/audit-dependency.json'):
                _Gemini.init_gemini_audit_dependency(gemini_working_directory)

            _Gemini.handler_cli_license_key()

    def flask_protect_extended(self, protect_mode=None) -> None:
        """
        This function is used to protect the Flask application from malicious requests

        :param protect_mode: This is the mode you want to use for the protection
        :return: The function is being returned.
        """
        def _gemini_self_protect(f):
            @wraps(f)
            def __gemini_self_protect(*args, **kwargs):
                _ip_address = _Gemini.get_flask_client_ip()
                if _Gemini.check_gemini_acl(_ip_address):
                    _ticket = _Gemini.generate_insident_ticket()
                    response = make_response("Your IP Address was blocked by Gemini \n The Runtime Application Self-Protection Solution \n\n Time: {} \n Your IP : {} \n\n Incident ID: {}".format(
                        _ticket["Time"], _ticket["IP"], _ticket["IncidentID"]), 200)
                    response = _Gemini.make_secure_response_header(response)
                    return response
                else:
                    global_protect_mode = _Gemini.get_gemini_config(
                        'gemini_global_protect_mode')
                    if protect_mode is None:
                        gemini_protect_mode = global_protect_mode
                    elif protect_mode is not None and global_protect_mode == 'off':
                        gemini_protect_mode = 'off'
                    else:
                        gemini_protect_mode = protect_mode
                    protect_request = _Gemini.__load_protect_flask_request__(
                        gemini_protect_mode)
                    if protect_request["Status"]:
                        response = make_response(f(*args, **kwargs))
                        protect_response = _Gemini.__load_protect_flask_response__(
                            response, gemini_protect_mode)
                        if protect_response["Status"]:
                            response = _Gemini.make_secure_response_header(
                                response)
                            return response
                        else:
                            current_time = protect_response["Ticket"]["Time"]
                            ip_address = protect_response["Ticket"]["IP"]
                            incedent_id = protect_response["Ticket"]["IncidentID"]
                            response = make_response("This request was blocked by Gemini \n The Runtime Application Self-Protection Solution \n\n Time: {} \n Your IP : {} \n\n Incident ID: {}".format(
                                current_time, ip_address, incedent_id), 200)
                            response = _Gemini.make_secure_response_header(
                                response)
                            return response
                    else:
                        current_time = protect_request["Ticket"]["Time"]
                        ip_address = protect_request["Ticket"]["IP"]
                        incedent_id = protect_request["Ticket"]["IncidentID"]
                        response = make_response("This request was blocked by Gemini \n The Runtime Application Self-Protection Solution \n\n Time: {} \n Your IP : {} \n\n Incident ID: {}".format(
                            current_time, ip_address, incedent_id), 200)
                        response = _Gemini.make_secure_response_header(
                            response)
                        return response
            return __gemini_self_protect
        return _gemini_self_protect

    def django_protect_extended(self):
        return True
