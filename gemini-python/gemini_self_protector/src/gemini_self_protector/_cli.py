import sys
from ._logger import logger
from ._gemini import _Gemini


class _Gemini_CLI(object):
    def __init__(self) -> None:
        logger.info(
            "[+] Running gemini-self protector - CLI Mode")
        is_install = _Gemini.get_gemini_config().isinstall
        if int(is_install) == 0:
            _Gemini.update_gemini_config({'running_mode': 'CLI'})
            _Gemini_CLI.handler_install_gemini_self_protector()
        else:
            _Gemini_CLI.handler_predict_server_health_check()
        mode = _Gemini.get_gemini_config().global_protect_mode
        logger.info(
            "[+] Gemini Global Protect Mode: {0}".format(mode))

    def handler_install_gemini_self_protector():
        try:
            isPredictServer = _Gemini.get_gemini_config().predict_server
            if isPredictServer:
                logger.info(
                    "[+] Predict server health check.....")
                if _Gemini.health_check_predict_server():
                    logger.info(
                        "[+] Predict server is online")
                else:
                    logger.info(
                        "[+] Predict server is offline")
            else:
                while True:
                    try:
                        protect_mode = input(
                            "[?] Please choose mode (monitor - protection): ")
                        sensitive_value = input(
                            "?] Please input sensitive value (0 - 100): ")
                        predict_server = input(
                            "?] Please input predict server (http://predict-server:5000): ")
                        predict_server_key_auth = input(
                            "?] Please input authentication key: ")
                    except Exception as e:
                        logger.error(
                            "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_CLI.handler_install_gemini_self_protector', e))
                        continue
                    else:
                        break

                if _Gemini.validator_protect_mode(protect_mode) and _Gemini.validator_sensitive_value(sensitive_value) and _Gemini.validator_predict_server(predict_server, predict_server_key_auth):
                    _Gemini.update_gemini_config({
                        "isinstall": True,
                        "global_protect_mode": protect_mode,
                        "sensitive_value": int(sensitive_value),
                        "predict_server": predict_server,
                        "predict_server_key_auth": predict_server_key_auth
                    })
                    logger.info(
                        "[+] Predict server is online")
                else:
                    _Gemini_CLI.handler_install_gemini_self_protector()

        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_CLI.handler_install_gemini_self_protector', e))

    def handler_predict_server_health_check():
        try:
            if _Gemini.health_check_predict_server():
                logger.info(
                    "[+] Connected to predict serve")
            else:
                logger.error(
                    "[x] Cannot connected to predict serve")
                while True:
                    try:
                        diagnostic = input(
                            "[?] Do you run diagnostic (y/N): ") or "y"
                    except Exception as e:
                        logger.error(
                            "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_CLI.handler_predict_server_health_check', e))
                        continue
                    else:
                        break
                if diagnostic == 'y' or diagnostic == 'Y':
                    code = _Gemini.diagnostic_predict_server()
                    if code == 200:
                        logger.info(
                            "[+] Connected to predict serve")
                    elif code == 400:
                        logger.info(
                            "[!] Please check error log on predict serve")
                        sys.exit()
                    elif code == 401:
                        logger.info(
                            "[!] Please check your authentication key")
                        sys.exit()
                    elif code == 500:
                        logger.info(
                            "[!] Please check error log on predict serve")
                        sys.exit()
                else:
                    while True:
                        try:
                            answer = input(
                                "[?] Do you want continue (y/N): ") or "y"
                        except Exception as e:
                            logger.error(
                                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_CLI.handler_predict_server_health_check', e))
                            continue
                        else:
                            break

                    if answer == 'N' or answer == 'n':
                        sys.exit()

        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_CLI.handler_predict_server_health_check', e))
