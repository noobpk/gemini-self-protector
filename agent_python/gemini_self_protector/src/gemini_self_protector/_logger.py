import os
import logging
from colorlog import ColoredFormatter


def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    color_formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s] [%(levelname)-4s]%(reset)s - %(message)s",
        datefmt='%d-%m-%y %H:%M:%S',
        reset=True,
        log_colors={
                'DEBUG':    'cyan',
                'INFO':     'green',
                'WARNING':  'bold_yellow',
                'ERROR':    'bold_red',
                'CRITICAL': 'bold_red',
        },
        secondary_log_colors={},
        style='%')
    logging_handler = logging.StreamHandler()
    logging_handler.setFormatter(color_formatter)
    logger.addHandler(logging_handler)

    # create running folder
    running_directory = os.getcwd()
    final_directory = os.path.join(running_directory, r'gemini_protector')
    if not os.path.exists(final_directory):
        os.makedirs(final_directory)

    # record error logg
    err_file_handler = logging.FileHandler(
        'gemini_protector/gemini_protector_err.log')
    err_file_handler.setLevel(logging.ERROR)
    file_format = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s')
    err_file_handler.setFormatter(file_format)
    logger.addHandler(err_file_handler)

    # record info logg
    info_file_handler = logging.FileHandler(
        'gemini_protector/gemini_protetor_info.log')
    info_file_handler.setLevel(logging.INFO)
    file_format = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s')
    info_file_handler.setFormatter(file_format)
    logger.addHandler(info_file_handler)

    # record warning logg
    warning_file_handler = logging.FileHandler(
        'gemini_protector/gemini_protetor_warning.log')
    warning_file_handler.setLevel(logging.INFO)
    file_format = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s')
    warning_file_handler.setFormatter(file_format)
    logger.addHandler(warning_file_handler)

    # record critical logg
    critical_file_handler = logging.FileHandler(
        'gemini_protector/gemini_protetor_critical.log')
    critical_file_handler.setLevel(logging.INFO)
    file_format = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s')
    critical_file_handler.setFormatter(file_format)
    logger.addHandler(critical_file_handler)


# setup logging for script
setup_logging()
logger = logging.getLogger(__name__)
