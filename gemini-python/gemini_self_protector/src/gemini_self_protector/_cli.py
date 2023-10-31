import sys
from ._logger import logger
from ._gemini import _Gemini
from tqdm import tqdm

class _Gemini_CLI(object):
    def __init__(self) -> None:
        for i in tqdm(range(100), colour="green", desc="Gemini Loading"):
            pass
        logger.info(
            "[+] Running gemini-self protector - CLI Mode")
        is_install = _Gemini.get_gemini_config().is_install
        _Gemini.update_gemini_config({'running_mode': 'CLI'})
        if int(is_install) == 0:
            _Gemini_CLI.handler_install_gemini_self_protector()
        else:
            is_use_g_wvd_serve = _Gemini.get_gemini_config().is_use_g_wvd_serve
            if int(is_use_g_wvd_serve) == 1:
                _Gemini_CLI.handler_g_wvd_serve_health()
            else:
                logger.info(
                    "[+] No connection to G-WVD")
        mode = _Gemini.get_gemini_config().global_protect_mode
        logger.info(
            "[+] Gemini Global Protect Mode: {0}".format(mode))

    def handler_install_gemini_self_protector():
        try:
            while True:
                try:
                    protect_mode = input(
                        "[?] Choose mode (monitor - protection - off): ")
                    is_use_g_wvd_serve = input(
                        "[?] Using G-WVD serve (y/N): ") or 'y'
                    if is_use_g_wvd_serve == 'y' or is_use_g_wvd_serve == 'Y':
                        sensitive_value = input(
                            "[?] Input sensitive value (0 - 100): ")
                        g_wvd_serve = input("[?] Input G-WVD serve: ")
                        g_serve_key = input("[?] Input G serve key: ")
                except Exception as e:
                    logger.error(
                        "[x_x] Something went wrong at {0}, Check your error message.\n Message - {1}".format('_Gemini_CLI.handler_install_gemini_self_protector', e))
                    continue
                else:
                    break

            if is_use_g_wvd_serve == 'n' or is_use_g_wvd_serve == 'N':
                if _Gemini.validator_protect_mode(protect_mode):
                    _Gemini.update_gemini_config({
                        "is_install": 1,
                        "is_use_g_wvd_serve": 0,
                        "global_protect_mode": protect_mode,
                    })
                else:
                    _Gemini_CLI.handler_install_gemini_self_protector()
            else:
                if _Gemini.validator_protect_mode(protect_mode) and _Gemini.validator_sensitive_value(sensitive_value) and _Gemini.validator_g_wvd_serve(g_wvd_serve, g_serve_key, _self_context=True):
                    _Gemini.update_gemini_config({
                        "is_install": 1,
                        "is_use_g_wvd_serve": 1,
                        "global_protect_mode": protect_mode,
                        "sensitive_value": int(sensitive_value),
                        "g_wvd_serve": g_wvd_serve,
                        "g_serve_key": g_serve_key
                    })
                else:
                    _Gemini_CLI.handler_install_gemini_self_protector()

        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_CLI.handler_install_gemini_self_protector', e))

    def handler_g_wvd_serve_health():
        try:
            if _Gemini.g_wvd_serve_health(_self_context=True):
                logger.info(
                    "[+] Connected to G-WVD")
            else:
                logger.error(
                    "[x_x] Cannot connect to G-WVD")
                while True:
                    try:
                        diagnostic = input(
                            "[?] Do you run diagnostic (y/N): ") or "y"
                    except Exception as e:
                        logger.error(
                            "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_CLI.handler_g_wvd_serve_health', e))
                        continue
                    else:
                        break
                if diagnostic == 'y' or diagnostic == 'Y':
                    code = _Gemini.g_serve_diagnostic()
                    if code == 200:
                        logger.info(
                            "[+] Connected to G-WVD")
                    elif code == 400:
                        logger.info(
                            "[!] Please check error log on G-WVD")
                        sys.exit()
                    elif code == 401:
                        logger.info(
                            "[!] Please check your G-WVD key")
                        sys.exit()
                    elif code == 500:
                        logger.info(
                            "[!] Please check error log on G-WVD")
                        sys.exit()
                    else:
                        while True:
                            try:
                                answer = input("[?] Do you want continue without G-WVD (y/N): ") or "y"
                            except Exception as e:
                                logger.error(
                                    "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_GUI.handler_g_wvd_serve_health', e))  
                                continue 
                            else:
                                break
                        if answer == 'N' or answer == 'n':
                            sys.exit()
                else:
                    while True:
                        try:
                            answer = input(
                                "[?] Do you want continue (y/N): ") or "y"
                        except Exception as e:
                            logger.error(
                                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_CLI.handler_g_wvd_serve_health', e))
                            continue
                        else:
                            break

                    if answer == 'N' or answer == 'n':
                        sys.exit()
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Gemini_CLI.handler_g_wvd_serve_health', e))
