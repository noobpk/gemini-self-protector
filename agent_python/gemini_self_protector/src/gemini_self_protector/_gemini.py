import jwt
from functools import wraps
from ._logger import logger
from flask import request, jsonify
from ._utils import _Utils
from datetime import datetime, timezone


# It's a class that contains a bunch of methods that are used to interact with the Gemini API
class _Gemini(object):

    def verify_license_key(license_key):
        if license_key:
            logger.info("[+] Gemini License Key: {}".format(license_key))
            if license_key == '988907ce-9803-11ed-a8fc-0242ac120002':
                # call api and return access_token
                access_token = jwt.encode(
                    {"license": license_key}, "secret", algorithm="HS256")
                return access_token
            else:
                logger.error("[x_x] Invalid License Key")
                return False
        else:
            return False

    def verify_protect_mode(protect_mode):
        """
        If the protect_mode is on, then it will return the protect_mode. If the protect_mode is monitor,
        then it will return the protect_mode. If the protect_mode is block, then it will return the
        protect_mode. If the protect_mode is off, then it will return the protect_mode. If the
        protect_mode is anything else, then it will return None.
        
        :param protect_mode: This is the mode in which the protector will run
        :return: The return value is the protect_mode variable.
        """
        if protect_mode == 'on':
            logger.info("[+] Gemini-Self-Protector is On")
            return protect_mode
        if protect_mode == 'monitor':
            logger.info("[+] Gemini-Self-Protector run on mode: MONITORING")
            return protect_mode
        elif protect_mode == 'block':
            logger.info("[+] Gemini-Self-Protector run on mode: BLOCKING")
            return protect_mode
        elif protect_mode == 'off':
            logger.info("[+] Gemini-Self-Protector is Off")
            return protect_mode
        else:
            logger.error(
                "[x_x] Invalid Protect Mode. Protect mode must be: on - monitor - block - off")
            logger.warning(
                "[!] Your App Currently Running Without Gemini-Self-Protector.")
            return None

    def verify_sensitive(sensitive):
        if 0 <= int(sensitive) <= 100:
            return int(sensitive)
        else:
            logger.error(
                "[x_x] Invalid Sensitive Value. Sensitive value from 0 to 100")
            return 0

    def __load_protect_flask__(gemini_protect_mode, sensitive_value):
        # It's checking if the protect_mode is on. If it is, then it will return an error.
        if gemini_protect_mode == 'on':
            logger.error(
                "[x_x] Protect mode for Method must be: monitor - block - off")
            pass
        elif gemini_protect_mode == 'monitor':
            logger.info("[+] Gemini-Self-Protector Mode MONITORING")
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
            
            if predict > sensitive_value:
                status = True
                return [status, current_time, ip_address, incident_id] 
            else:
                status = True
                return [status, ip_address, incident_id]
        elif gemini_protect_mode == 'block':
            logger.info("[+] Gemini-Self-Protector Mode BLOCKING")
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
            if predict > sensitive_value:
                status = False
                return [status, current_time, ip_address, incident_id] 
            else:
                status = True
                return [status, current_time, ip_address, incident_id] 
        elif gemini_protect_mode == 'off':
            logger.info("[+] Gemini-Self-Protector is Off")
            pass
        else:
            logger.error(
                "[x_x] Invalid Protect Mode. Protect mode must be: monitor - block - off")
            pass
