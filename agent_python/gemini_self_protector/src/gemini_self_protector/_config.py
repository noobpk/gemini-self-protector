import os
import yaml
from ._logger import logger
import json

class _Config(object):
    def __init__(self, working_directory, config_content):
        config_file = working_directory+'/config.yml'
        try:
            with open(config_file, "w") as file:
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

    def init_data_store(working_directory):
        data_file = working_directory+'/data.json'
        try:
            # create an empty dictionary
            data = {"gemini_data_stored":[]}

            # Write the empty dictionary to the new file
            with open(data_file, "w") as f:
                # use pickle to dump the dictionary to the file
                json.dump(data, f,  indent=4)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))

    def update_data_store(_dict):
        try:
            data_store_path = _Config.get_config('gemini_data_store_path')
            with open(data_store_path, "r") as f:
                existing_data = json.load(f)

            existing_data["gemini_data_stored"].append(_dict)            
            # Write the add new data back to the file
            with open(data_store_path, "w") as f:
                json.dump(existing_data, f, indent = 4)
        except Exception as e:
            logger.error("[x_x] Something went wrong, please check your error message.\n Message - {0}".format(e))