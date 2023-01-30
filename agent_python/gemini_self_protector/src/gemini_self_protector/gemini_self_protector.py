import jwt
from functools import wraps
from ._logger import logger
from flask import request
from ._utils import _Utils


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

    def __load_protect__(gemini_protect_mode):
        if gemini_protect_mode == 'on':
            logger.error(
                "[x_x] Protect mode for Method must be: monitor - block - off")
        elif gemini_protect_mode == 'monitor':
            logger.info("[+] Gemini-Self-Protector Mode MONITORING")
            data = request.data
            payload = _Utils.decoder(data.decode("utf-8"))
            predict = _Utils.web_vuln_detect_predict(payload)
            logger.info("[+] Accuracy: {}".format(predict))
        elif gemini_protect_mode == 'block':
            logger.info("[+] Gemini-Self-Protector Mode BLOCKING")
        elif gemini_protect_mode == 'off':
            logger.info("[+] Gemini-Self-Protector is Off")
        else:
            logger.error(
                "[x_x] Invalid Protect Mode. Protect mode must be: monitor - block - off")
