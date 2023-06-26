from ._logger import logger
from ._gemini import _Gemini


class _Gemini_CLI(object):
    def __init__(self) -> None:
        logger.info(
            "[+] Running gemini-self protector - CLI Mode")
        _Gemini_CLI.handler_cli_license_key()
        _Gemini_CLI.handler_cli_predict_server()
        mode = _Gemini.get_gemini_config().global_protect_mode
        logger.info(
            "[+] Gemini Global Protect Mode: {0}".format(mode))

    def handler_cli_license_key():
        try:
            isKey = _Gemini.get_gemini_config().license_key
            if isKey is None:
                while True:
                    try:
                        key = input("Please enter your license key: ")
                    except Exception as e:
                        logger.error(
                            "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_CLI.handler_cli_license_key', e))
                        continue
                    else:
                        break

                if _Gemini.validator_license_key(key):
                    logger.info(
                        "[+] License Activate Successful. Thank for using Gemini-Self Protector")
                else:
                    _Gemini_CLI.handler_cli_license_key()
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
                                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_CLI.handler_cli_license_key', e))
                            continue
                        else:
                            break

                    if _Gemini.validator_license_key(key):
                        logger.info(
                            "[+] License Activate Successful. Thank for using Gemini-Self Protector")
                    else:
                        _Gemini_CLI.handler_cli_license_key()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_CLI.handler_cli_license_key', e))

    def handler_cli_predict_server():
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
                        server = input("Please enter predict server: ")
                    except Exception as e:
                        logger.error(
                            "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_CLI.handler_cli_predict_server', e))
                        continue
                    else:
                        break

                if _Gemini.validator_predict_server(server):
                    logger.info(
                        "[+] Predict server is online")
                else:
                    _Gemini_CLI.handler_cli_predict_server()

        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_CLI.handler_cli_predict_server', e))
