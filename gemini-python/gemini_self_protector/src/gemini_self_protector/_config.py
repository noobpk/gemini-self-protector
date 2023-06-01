import os
import yaml
from ._logger import logger
import json
from ipaddress import ip_address
from datetime import datetime

class _Config(object):

    def __init__(self, working_directory, config_content):
        """
        It takes a working directory and a config content, and then it writes the config content to a
        file called config.yml in the working directory.

        :param working_directory: /home/user/project/
        :param config_content: This is a dictionary that contains the configuration parameters
        """
        config_file = working_directory+'/config.yml'
        try:
            with open(config_file, "w") as file:
                yaml.dump(config_content, file)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.__init__', e))

    def get_config(config_key) -> None:
        """
        It reads a config file and returns the value of the key that is passed to it

        :param config_key: The key you want to get the value of
        :return: The value of the key in the config.yml file.
        """
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
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.get_config', e))

    def update_config(config_content):
        """
        It takes a dictionary as an argument, and updates the YAML file with the new data

        :param config_content: This is the dictionary that contains the new data that you want to update
        in the YAML file
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
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.update_config', e))


    def init_data_store(working_directory):
        """
        It creates a new file called data.json in the working directory and writes an empty dictionary
        to it

        :param working_directory: The directory where the data.json file will be stored
        """
        data_file = working_directory+'/data.json'
        try:
            # create an empty dictionary
            data = {"gemini_data_stored":[]}

            # Write the empty dictionary to the new file
            with open(data_file, "w") as f:
                # use pickle to dump the dictionary to the file
                json.dump(data, f,  indent=4)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.init_data_store', e))

    def update_data_store(_dict):
        """
        It takes a dictionary as an argument, opens a json file, loads the json file into a variable,
        appends the dictionary to the variable, and then writes the variable back to the json file

        :param _dict: This is the dictionary that you want to add to the existing data store
        """
        try:
            data_store_path = _Config.get_config('gemini_data_store_path')
            with open(data_store_path, "r") as f:
                existing_data = json.load(f)

            existing_data["gemini_data_stored"].append(_dict)
            # Write the add new data back to the file
            with open(data_store_path, "w") as f:
                json.dump(existing_data, f, indent = 4)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.update_data_store', e))

    def init_acl(working_directory):
        """
        This function creates an empty dictionary and writes it to a file called acl.json

        :param working_directory: The directory where the file will be created
        """
        data_file = working_directory+'/acl.json'
        try:
            # create an empty dictionary
            data = {"gemini_acl":[]}

            # Write the empty dictionary to the new file
            with open(data_file, "w") as f:
                # use pickle to dump the dictionary to the file
                json.dump(data, f,  indent=4)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.init_acl', e))

    def update_acl(_dict):
        """
        It reads the existing JSON file, appends the new data to the existing data, and writes the new
        data back to the file

        :param _dict: This is the dictionary that you want to add to the existing JSON file
        """
        try:
            acl_path = _Config.get_config('gemini_acl_path')
            with open(acl_path, "r") as f:
                existing_data = json.load(f)

            existing_data["gemini_acl"].append(_dict)
            # Write the add new data back to the file
            with open(acl_path, "w") as f:
                json.dump(existing_data, f, indent = 4)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.update_acl', e))

    def check_acl(_ip_address) -> None:
        """
        It reads a JSON file, converts the IP addresses in the file to IP objects, and then checks if
        the IP address passed to the function is in the list of IP objects

        :param _ip_address: The IP address that you want to check against the ACL
        :return: True or False
        """
        try:
            acl_path = _Config.get_config('gemini_acl_path')
            with open(acl_path, "r") as f:
                acl_data = json.load(f)

            ip_list = [ip_address(entry['Ip']) for entry in acl_data['gemini_acl']]
            if ip_address(_ip_address) in ip_list:
                return True
            else:
                return False
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.check_acl', e))

    def remove_acl(_ip_address):
        """
        It opens a json file, reads the contents, removes an object from the json file, and then writes
        the contents back to the file

        :param _ip_address: The IP address to be removed from the ACL
        """
        try:
            acl_path = _Config.get_config('gemini_acl_path')
            with open(acl_path, "r") as f:
                acl_data = json.load(f)

            for acl in acl_data["gemini_acl"]:
                if acl.get("Ip") == _ip_address:
                    acl_data["gemini_acl"].remove(acl)
            with open(acl_path, "w") as f:
                json.dump(acl_data, f, indent = 4)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.remove_acl', e))

    def init_audit_dependency(working_directory):
        """
        This function creates an empty json file called audit_dependency.json in the working directory

        :param working_directory: The directory where the audit_dependency.json file is located
        """
        data_file = working_directory+'/audit_dependency.json'
        try:
            # create an empty dictionary
            data = {"gemini_audit_dependency":[]}

            # Write the empty dictionary to the new file
            with open(data_file, "w") as f:
                # use pickle to dump the dictionary to the file
                json.dump(data, f,  indent=4)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.init_audit_dependency', e))


    def update_audit_dependency(_dict):
        """
        It takes a dictionary as an argument, and appends it to a JSON file

        :param _dict: This is the dictionary that you want to add to the json file
        """
        try:
            audit_dependency_path = _Config.get_config('gemini_audit_dependency')
            print()
            now = datetime.now()
            current_time = now.strftime("%Y-%m-%d %H:%M:%S")
            with open(audit_dependency_path, "r") as f:
                existing_data = json.load(f)

            existing_data["gemini_audit_dependency"].append({str(current_time):_dict})
            # Write the add new data back to the file
            with open(audit_dependency_path, "w") as f:
                json.dump(existing_data, f, indent = 4)
        except Exception as e:
            logger.error(
                "[x_x] Something went wrong at {0}, please check your error message.\n Message - {1}".format('_Config.update_audit_dependency', e))
