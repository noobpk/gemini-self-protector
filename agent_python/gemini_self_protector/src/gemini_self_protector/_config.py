import os
import yaml
from ._logger import logger

class _Config(object):
    def __init__(self, working_directory):
        self.config_file = working_directory+'/config.yml'

    def init_config(self, config_content):
        """
        It takes a working directory and a dictionary of key-value pairs and updates the config.yml file
        in the working directory with the key-value pairs
        
        :param working_directory: The directory where the config.yml file is located
        :param config_content: This is the new data that you want to add to the YAML file
        """
        try:
            with open(self.config_file, "w") as file:
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
            config_path = _Config.get_config('gemini_config_path')
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
            current_value = _Config.get_config('gemini_normal_request')
            _Config.update_config({'gemini_normal_request': current_value+1})
            logger.info("[+] gemini_normal_request was updated")
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def update_abnormal_request():
        try:
            current_value = _Config.get_config('gemini_abnormal_request')
            _Config.update_config({'gemini_abnormal_request': current_value+1})
            logger.info("[+] gemini_abnormal_request was updated")
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))