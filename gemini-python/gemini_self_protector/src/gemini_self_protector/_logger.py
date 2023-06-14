import os
import logging
from colorlog import ColoredFormatter


def setup_logging():
    """
    It sets up the logging module.
    """
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

    # Creating a directory called gemini_protector/log in the current working directory.
    running_directory = os.getcwd()
    gemini_log_directory = os.path.join(
        running_directory, r'gemini-protector', r'log')
    if not os.path.exists(gemini_log_directory):
        os.makedirs(gemini_log_directory)

    # Creating a file handler for the error log.
    err_file_handler = logging.FileHandler(
        'gemini-protector/log/gemini-protector_err.log')
    err_file_handler.setLevel(logging.ERROR)
    file_format = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s')
    err_file_handler.setFormatter(file_format)
    logger.addHandler(err_file_handler)

    # Creating a file handler for the info log.
    info_file_handler = logging.FileHandler(
        'gemini-protector/log/gemini-protetor-info.log')
    info_file_handler.setLevel(logging.INFO)
    file_format = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s')
    info_file_handler.setFormatter(file_format)
    logger.addHandler(info_file_handler)

    # Creating a file handler for the warning log.
    warning_file_handler = logging.FileHandler(
        'gemini-protector/log/gemini-protetor-warning.log')
    warning_file_handler.setLevel(logging.INFO)
    file_format = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s')
    warning_file_handler.setFormatter(file_format)
    logger.addHandler(warning_file_handler)

    # Creating a file handler for the critical log.
    critical_file_handler = logging.FileHandler(
        'gemini-protector/log/gemini-protetor-critical.log')
    critical_file_handler.setLevel(logging.INFO)
    file_format = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s')
    critical_file_handler.setFormatter(file_format)
    logger.addHandler(critical_file_handler)


# Setting up the logging module.
setup_logging()
logger = logging.getLogger(__name__)
